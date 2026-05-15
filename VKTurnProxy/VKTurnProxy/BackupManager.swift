// BackupManager.swift
//
// Export/Import/Reset of app state for the Settings → Backup & Restore
// section.
//
// Export builds a SafeBackupConfig snapshot with non-secret local preferences
// only. It intentionally excludes WireGuard keys, VK links, WRAP keys,
// creds-pool.json, and vk_profile.json. Output is a temp .json file fed into
// UIActivityViewController (Share Sheet) so the user picks the destination.
//
// Import accepts the current settings-only format and legacy "full" backups.
// Settings-only imports never overwrite secrets or shared cache/profile files.
// Legacy full imports retain old restore behavior for manual recovery.
//
// Reset just deletes creds-pool.json. The pool gets rebuilt on next
// connect via the normal VK API + PoW path. No UserDefaults changes.

import Darwin
import Foundation

enum BackupError: Error, LocalizedError {
    case noContainer
    case writeFailed(String)
    case readFailed(String)
    case decodeFailed(String)
    case versionMismatch(Int)
    case payloadTooLarge(kind: String, maxBytes: Int)
    case validationFailed(String)

    var errorDescription: String? {
        switch self {
        case .noContainer:
            return "App Group container is unavailable. Check entitlements."
        case .writeFailed(let detail):
            return "Failed to write file: \(detail)"
        case .readFailed(let detail):
            return "Failed to read file: \(detail)"
        case .decodeFailed(let detail):
            return "Backup file is invalid or corrupted: \(detail)"
        case .versionMismatch(let v):
            return "Backup file version \(v) is not supported by this build."
        case .payloadTooLarge(let kind, let maxBytes):
            return "\(kind) is too large. Maximum supported size is \(maxBytes) bytes."
        case .validationFailed(let detail):
            return "Import payload failed validation: \(detail)"
        }
    }
}

enum BackupManager {
    /// Schema version of AppConfig itself. Bump when the wrapper shape
    /// changes (new top-level fields, restructured settings, etc.).
    static let supportedConfigVersion = 1
    private static let settingsOnlyBackupType = "settings"
    private static let legacyFullBackupType = "full"
    private static let connectionLinkType = "connection"
    private static let maxBackupFileBytes = 512 * 1024
    private static let maxConnectionLinkInputCharacters = 64 * 1024
    private static let maxConnectionLinkBase64Characters = 48 * 1024
    private static let maxConnectionLinkJSONBytes = 32 * 1024
    private static let maxShortStringLength = 1024
    private static let maxURLLength = 4096
    private static let maxListItems = 32
    private static let maxCredPoolEntries = 128
    private static let maxVKProfileFieldLength = 64 * 1024
    private static let hexCharacters = CharacterSet(charactersIn: "0123456789abcdefABCDEF")

    private struct BackupEnvelope: Decodable {
        let version: Int
        let type: String
    }

    /// Path to the App Group's creds-pool.json. Mirrors the Go-side
    /// `filepath.Dir(logFilePath) + "/creds-pool.json"` and the Swift-side
    /// `CredCache.cacheURL`. Kept here as a private duplicate so the
    /// backup logic is self-contained and won't break if CredCache ever
    /// computes the path differently.
    private static var credsPoolURL: URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.vkturnproxy.app"
        )?.appendingPathComponent("creds-pool.json")
    }

    // MARK: - Build current snapshot

    /// Reads only non-secret @AppStorage values via UserDefaults.standard
    /// (since @AppStorage is a thin wrapper over UserDefaults). Do not add
    /// keys, VK links, TURN credentials, or captured browser profiles here.
    static func currentSafeConfig() -> SafeBackupConfig {
        let d = UserDefaults.standard
        let settings = SafeBackupSettings(
            // Default values must match SettingsView's AppStorage defaults
            // — UserDefaults.string(forKey:) returns nil for unset keys
            // (unlike @AppStorage which returns the default). Using the
            // same defaults here ensures the export captures the in-app
            // state even if the user never opened Settings.
            tunnelAddress: d.string(forKey: "tunnelAddress") ?? "192.168.102.3/24",
            dnsServers: d.string(forKey: "dnsServers") ?? "1.1.1.1",
            allowedIPs: d.string(forKey: "allowedIPs") ?? "0.0.0.0/0",
            // Bool defaults: UserDefaults.bool(forKey:) returns false for
            // unset, but useDTLS defaults to true in @AppStorage. Use
            // object(forKey:) to distinguish "set to false" from "unset".
            useDTLS: (d.object(forKey: "useDTLS") as? Bool) ?? true,
            numConnections: (d.object(forKey: "numConnections") as? Int) ?? 30,
            credPoolCooldownSeconds: (d.object(forKey: "credPoolCooldownSeconds") as? Int) ?? 150,
            // WRAP defaults match SettingsView's @AppStorage defaults
            // (false / empty). Same object(forKey:) trick as useDTLS to
            // distinguish "explicitly set false" from "never set" — though
            // for a default of false the difference is invisible, the
            // pattern stays consistent with surrounding code.
            useWrap: (d.object(forKey: "useWrap") as? Bool) ?? false
        )

        return SafeBackupConfig(
            version: supportedConfigVersion,
            type: settingsOnlyBackupType,
            exportedAt: Int64(Date().timeIntervalSince1970),
            settings: settings
        )
    }

    static func isSettingsOnly(_ config: AppConfig) -> Bool {
        config.type == settingsOnlyBackupType
    }

    // MARK: - Export

    /// Encodes currentSafeConfig() to a pretty-printed JSON file in the temp
    /// directory and returns its URL. Caller passes the URL to
    /// UIActivityViewController. The temp file contains no plaintext secrets.
    static func exportToTempFile() throws -> URL {
        let config = currentSafeConfig()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(config)
        } catch {
            throw BackupError.writeFailed("encode: \(error.localizedDescription)")
        }

        // Filename includes a timestamp so the user gets distinguishable
        // files when they export multiple times — useful when iterating
        // on settings and AirDropping each iteration to the Mac.
        let timestamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let filename = "vkturnproxy-settings-backup-\(timestamp).json"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(filename)

        do {
            try data.write(to: url, options: .atomic)
        } catch {
            throw BackupError.writeFailed(error.localizedDescription)
        }
        SharedLogger.shared.log("[AppDebug] Backup: exported settings-only backup (\(data.count) bytes) to \(url.lastPathComponent)")
        return url
    }

    // MARK: - Import

    /// Reads JSON at the given file URL. Used by the document picker
    /// callback after the user selects a file. Validates schema version
    /// before applying anything — a too-new backup is rejected before
    /// any state is changed.
    static func importFromFileURL(_ url: URL) throws -> AppConfig {
        // Document picker hands us a security-scoped URL when the file
        // lives outside our sandbox (iCloud Drive, On My iPhone, etc.).
        // Without start/stopAccessing, Data(contentsOf:) returns
        // "Operation not permitted" for those sources.
        let needsScope = url.startAccessingSecurityScopedResource()
        defer {
            if needsScope {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            try validateFileSize(url, kind: "Backup file", maxBytes: maxBackupFileBytes)
            data = try Data(contentsOf: url)
        } catch {
            if let backupError = error as? BackupError {
                throw backupError
            }
            throw BackupError.readFailed(error.localizedDescription)
        }
        try validatePayloadSize(data.count, kind: "Backup file", maxBytes: maxBackupFileBytes)

        let decoder = JSONDecoder()
        let envelope: BackupEnvelope
        do {
            envelope = try decoder.decode(BackupEnvelope.self, from: data)
        } catch {
            throw BackupError.decodeFailed(error.localizedDescription)
        }

        if envelope.version != supportedConfigVersion {
            throw BackupError.versionMismatch(envelope.version)
        }
        try validateBackupJSONKeys(data, type: envelope.type)

        switch envelope.type {
        case settingsOnlyBackupType:
            let safe: SafeBackupConfig
            do {
                safe = try decoder.decode(SafeBackupConfig.self, from: data)
            } catch {
                throw BackupError.decodeFailed("Settings backup JSON: \(error.localizedDescription)")
            }
            try validateSafeBackup(safe)
            return AppConfig(
                version: safe.version,
                type: safe.type,
                exportedAt: safe.exportedAt,
                settings: AppSettings(
                    privateKey: "",
                    peerPublicKey: "",
                    presharedKey: "",
                    tunnelAddress: safe.settings.tunnelAddress,
                    dnsServers: safe.settings.dnsServers,
                    allowedIPs: safe.settings.allowedIPs,
                    vkLink: "",
                    peerAddress: "",
                    useDTLS: safe.settings.useDTLS,
                    numConnections: safe.settings.numConnections,
                    credPoolCooldownSeconds: safe.settings.credPoolCooldownSeconds,
                    useWrap: safe.settings.useWrap,
                    wrapKeyHex: nil
                ),
                turnPool: nil,
                vkProfile: nil
            )
        case legacyFullBackupType:
            do {
                let config = try decoder.decode(AppConfig.self, from: data)
                try validateAppConfig(config)
                return config
            } catch {
                if let backupError = error as? BackupError {
                    throw backupError
                }
                throw BackupError.decodeFailed("Legacy full backup JSON: \(error.localizedDescription)")
            }
        default:
            throw BackupError.decodeFailed("Unsupported backup type '\(envelope.type)'")
        }
    }

    /// Applies the AppConfig to Keychain, UserDefaults, and creds-pool.json. Called
    /// after the user confirms the import in the alert dialog. Logs both
    /// success and per-step failures so post-mortem analysis from vpn.log
    /// can pinpoint what landed and what didn't.
    static func applyConfig(_ config: AppConfig) throws {
        try validateAppConfig(config)
        let d = UserDefaults.standard
        let s = config.settings
        let settingsOnly = isSettingsOnly(config)

        if !settingsOnly {
            try KeychainStore.set(s.privateKey, for: .privateKey)
            try KeychainStore.set(s.presharedKey, for: .presharedKey)
            try KeychainStore.set(s.vkLink, for: .vkLink)
            d.set(s.peerPublicKey, forKey: "peerPublicKey")
            d.set(s.peerAddress, forKey: "peerAddress")
        }

        d.set(s.tunnelAddress, forKey: "tunnelAddress")
        d.set(s.dnsServers, forKey: "dnsServers")
        d.set(s.allowedIPs, forKey: "allowedIPs")
        d.set(s.useDTLS, forKey: "useDTLS")
        d.set(s.numConnections, forKey: "numConnections")
        d.set(s.credPoolCooldownSeconds, forKey: "credPoolCooldownSeconds")
        // WRAP fields: nil → leave UserDefaults alone so the AppStorage
        // default kicks in, matching the behaviour for an older backup
        // that never had these keys. Non-nil → write through, including
        // false / empty if the user explicitly set them that way.
        if let v = s.useWrap { d.set(v, forKey: "useWrap") }
        if !settingsOnly, let v = s.wrapKeyHex {
            try KeychainStore.set(v, for: .wrapKeyHex)
        }
        KeychainStore.clearLegacyUserDefaultsSecrets()

        let kind = settingsOnly ? "settings-only" : "legacy full"
        SharedLogger.shared.log("[AppDebug] Backup: applied \(kind) settings (numConnections=\(s.numConnections), cooldown=\(s.credPoolCooldownSeconds)s, useDTLS=\(s.useDTLS), useWrap=\(s.useWrap ?? false))")

        if settingsOnly {
            SharedLogger.shared.log("[AppDebug] Backup: settings-only import left keys, links, TURN cache, and captured browser profile unchanged")
            return
        }

        // creds-pool.json: write only if backup contained one. If the
        // backup has nil turnPool (e.g. user exported on a fresh install
        // before any successful connect), leave the existing cache
        // alone — overwriting with empty would defeat the point of
        // restoring on a fresh device that DOES have a cache from a
        // previous install.
        guard let pool = config.turnPool else {
            SharedLogger.shared.log("[AppDebug] Backup: turn_pool absent in backup, leaving creds-pool.json unchanged")
            return
        }
        guard let url = credsPoolURL else {
            throw BackupError.noContainer
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(pool)
        } catch {
            throw BackupError.writeFailed("encode turn_pool: \(error.localizedDescription)")
        }

        // tmp+rename mirrors Go-side saveToDisk's atomicity: a reader
        // (the extension when it next launches) sees either the old file
        // or the new, never a torn write.
        let tmpURL = url.appendingPathExtension("tmp")
        do {
            try? FileManager.default.removeItem(at: tmpURL)
            try data.write(to: tmpURL, options: .atomic)
            // Replace existing file. _ = is fine — replaceItemAt either
            // succeeds, throws, or returns the result URL; we don't need
            // the URL since we know our target.
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
        } catch {
            try? FileManager.default.removeItem(at: tmpURL)
            throw BackupError.writeFailed("write creds-pool.json: \(error.localizedDescription)")
        }
        SharedLogger.shared.log("[AppDebug] Backup: restored creds-pool.json with \(pool.creds.count) slots")

        // Captured browser profile: write only if the backup contained one.
        // Same nil-tolerance reasoning as turn_pool — older backups
        // exported before the field shipped just leave the existing
        // vk_profile.json (if any) alone. Failure here is logged but
        // doesn't abort the import: the worst case is a stale or absent
        // profile, which the auto-solver tolerates by falling back to
        // generated browser_fp.
        if let entry = config.vkProfile {
            do {
                try VKProfileCache.applyFromBackup(entry)
                SharedLogger.shared.log("[AppDebug] Backup: restored vk_profile.json (device=\(entry.device.count)c, browser_fp=\(entry.browser_fp.count)c)")
            } catch {
                SharedLogger.shared.log("[AppDebug] Backup: vk_profile.json write failed (non-fatal): \(error.localizedDescription)")
            }
        } else {
            SharedLogger.shared.log("[AppDebug] Backup: vk_profile absent in backup, leaving vk_profile.json unchanged")
        }
    }

    // MARK: - Reset TURN Cache

    /// Deletes creds-pool.json. The pool will be rebuilt from scratch on
    /// next connect via the normal VK API path. Idempotent — succeeds
    /// silently if the file was already gone (ENOENT is treated as success
    /// since the post-condition "no creds-pool.json exists" holds).
    static func resetTurnCache() throws {
        guard let url = credsPoolURL else {
            throw BackupError.noContainer
        }
        do {
            try FileManager.default.removeItem(at: url)
            SharedLogger.shared.log("[AppDebug] Backup: deleted creds-pool.json (Reset TURN Cache)")
        } catch CocoaError.fileNoSuchFile {
            SharedLogger.shared.log("[AppDebug] Backup: Reset TURN Cache — file already absent")
        } catch let nsErr as NSError where nsErr.code == NSFileNoSuchFileError {
            SharedLogger.shared.log("[AppDebug] Backup: Reset TURN Cache — file already absent")
        } catch {
            throw BackupError.writeFailed("delete creds-pool.json: \(error.localizedDescription)")
        }
    }

    // MARK: - Reset Captured Browser Profile

    /// Deletes vk_profile.json. The auto-PoW solver will fall back to
    /// its generated browser_fp + canned device descriptor, with the
    /// pre-build-55 BOT-detection rate (~6%) — until the next manual
    /// captcha solve in CaptchaWKWebView re-captures fresh values.
    /// Idempotent same way as resetTurnCache.
    static func resetCapturedProfile() throws {
        try VKProfileCache.delete()
    }

    // MARK: - 1-Click Connection Link

    /// Parses a `vkturnproxy://import?data=<base64>` URL. The system
    /// hands one of these to .onOpenURL whenever the user taps a link
    /// with the registered scheme. Throws on any structural error so
    /// the caller can show a single "Connection Link Invalid" alert
    /// with the underlying message.
    static func parseConnectionLink(from url: URL) throws -> ConnectionLink {
        try validatePayloadSize(url.absoluteString.count, kind: "Connection link", maxBytes: maxConnectionLinkInputCharacters)
        guard url.scheme?.lowercased() == "vkturnproxy" else {
            throw BackupError.decodeFailed("URL scheme is not vkturnproxy://")
        }
        // Accept both vkturnproxy://import?data=… and the looser
        // vkturnproxy:?data=… form. URL.host is "import" for the first
        // and nil for the second; both should work.
        if let host = url.host, host.lowercased() != "import" {
            throw BackupError.decodeFailed("URL host must be 'import' (got '\(host)')")
        }
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let dataItem = comps.queryItems?.first(where: { $0.name == "data" }),
              let b64 = dataItem.value, !b64.isEmpty else {
            throw BackupError.decodeFailed("URL is missing the 'data' query parameter")
        }
        return try parseConnectionLinkBase64(b64)
    }

    /// Same as parseConnectionLink(from:) but takes the raw clipboard
    /// string. Tolerant of either a full URL ("vkturnproxy://…") or a
    /// bare base64 blob — the user might have copied either form.
    static func parseConnectionLinkString(_ raw: String) throws -> ConnectionLink {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        try validatePayloadSize(trimmed.count, kind: "Connection link", maxBytes: maxConnectionLinkInputCharacters)
        if let url = URL(string: trimmed), url.scheme?.lowercased() == "vkturnproxy" {
            return try parseConnectionLink(from: url)
        }
        // No URL prefix — treat input as raw base64.
        return try parseConnectionLinkBase64(trimmed)
    }

    /// Decodes a base64 string (standard or url-safe, with or without
    /// padding) into the ConnectionLink JSON. Common bottom layer for
    /// both URL- and clipboard-string entry points.
    private static func parseConnectionLinkBase64(_ b64Input: String) throws -> ConnectionLink {
        // Normalise to standard base64 with padding before Foundation's
        // Data(base64Encoded:) — it's strict about both.
        var b64 = b64Input.filter { !$0.isWhitespace }
                          .replacingOccurrences(of: "-", with: "+")
                          .replacingOccurrences(of: "_", with: "/")
        try validatePayloadSize(b64.count, kind: "Connection link base64", maxBytes: maxConnectionLinkBase64Characters)
        let padNeeded = (4 - b64.count % 4) % 4
        b64 += String(repeating: "=", count: padNeeded)
        guard let data = Data(base64Encoded: b64) else {
            throw BackupError.decodeFailed("Invalid base64 in connection link")
        }
        try validatePayloadSize(data.count, kind: "Connection link JSON", maxBytes: maxConnectionLinkJSONBytes)
        try validateConnectionLinkJSONKeys(data)
        let link: ConnectionLink
        do {
            link = try JSONDecoder().decode(ConnectionLink.self, from: data)
        } catch {
            throw BackupError.decodeFailed("Connection link JSON: \(error.localizedDescription)")
        }
        if link.version != supportedConfigVersion {
            throw BackupError.versionMismatch(link.version)
        }
        try validateConnectionLink(link)
        return link
    }

    /// Applies the ConnectionLink to Keychain + UserDefaults. Does NOT touch
    /// creds-pool.json or vk_profile.json — those belong to the
    /// receiving device and rebuild themselves on first connect after
    /// the new settings take effect. Optional fields (dnsServers,
    /// numConnections) only overwrite when present in the link;
    /// absent values preserve whatever the device already had.
    static func applyConnectionLink(_ link: ConnectionLink) throws {
        try validateConnectionLink(link)
        let d = UserDefaults.standard
        let s = link.settings
        try KeychainStore.set(s.privateKey, for: .privateKey)
        try KeychainStore.set(s.presharedKey, for: .presharedKey)
        try KeychainStore.set(s.vkLink, for: .vkLink)
        try KeychainStore.set(s.wrapKeyHex, for: .wrapKeyHex)
        d.set(s.peerPublicKey, forKey: "peerPublicKey")
        d.set(s.tunnelAddress, forKey: "tunnelAddress")
        d.set(s.allowedIPs, forKey: "allowedIPs")
        d.set(s.peerAddress, forKey: "peerAddress")
        d.set(s.useDTLS, forKey: "useDTLS")
        d.set(s.useWrap, forKey: "useWrap")
        if let v = s.dnsServers { d.set(v, forKey: "dnsServers") }
        if let v = s.numConnections { d.set(v, forKey: "numConnections") }
        KeychainStore.clearLegacyUserDefaultsSecrets()
        // Do not log vkLink, keys, WRAP key, or peerAddress here: connection
        // links are secret-bearing import payloads.
        let nc = s.numConnections.map(String.init) ?? "(kept default)"
        let dn = s.dnsServers ?? "(kept default)"
        SharedLogger.shared.log("[AppDebug] Backup: applied connection link (peer=<redacted>, useDTLS=\(s.useDTLS), useWrap=\(s.useWrap), numConnections=\(nc), dnsServers=\(dn))")
    }

    // MARK: - Import validation

    private static func validatePayloadSize(_ count: Int, kind: String, maxBytes: Int) throws {
        if count > maxBytes {
            throw BackupError.payloadTooLarge(kind: kind, maxBytes: maxBytes)
        }
    }

    private static func validateFileSize(_ url: URL, kind: String, maxBytes: Int) throws {
        let values = try? url.resourceValues(forKeys: [.fileSizeKey, .totalFileAllocatedSizeKey])
        let size = values?.fileSize ?? values?.totalFileAllocatedSize
        if let size {
            try validatePayloadSize(size, kind: kind, maxBytes: maxBytes)
        }
    }

    private static func validateBackupJSONKeys(_ data: Data, type: String) throws {
        let root = try jsonObjectDictionary(data, context: "backup root")
        switch type {
        case settingsOnlyBackupType:
            try validateKeys(root, allowed: ["version", "type", "exported_at", "settings"], context: "settings backup")
            try validateNestedKeys(root["settings"], allowed: [
                "tunnelAddress", "dnsServers", "allowedIPs", "useDTLS",
                "numConnections", "credPoolCooldownSeconds", "useWrap"
            ], context: "settings backup settings")
        case legacyFullBackupType:
            try validateKeys(root, allowed: ["version", "type", "exported_at", "settings", "turn_pool", "vk_profile"], context: "legacy backup")
            try validateNestedKeys(root["settings"], allowed: [
                "privateKey", "peerPublicKey", "presharedKey", "tunnelAddress",
                "dnsServers", "allowedIPs", "vkLink", "peerAddress", "useDTLS",
                "numConnections", "credPoolCooldownSeconds", "useWrap", "wrapKeyHex"
            ], context: "legacy backup settings")
            if let pool = root["turn_pool"], !(pool is NSNull) {
                try validateCredPoolJSONKeys(pool)
            }
            if let profile = root["vk_profile"], !(profile is NSNull) {
                try validateNestedKeys(profile, allowed: ["device", "browser_fp", "user_agent", "captured_at"], context: "vk_profile")
            }
        default:
            throw BackupError.decodeFailed("Unsupported backup type '\(type)'")
        }
    }

    private static func validateConnectionLinkJSONKeys(_ data: Data) throws {
        let root = try jsonObjectDictionary(data, context: "connection link root")
        try validateKeys(root, allowed: ["version", "type", "settings"], context: "connection link")
        try validateNestedKeys(root["settings"], allowed: [
            "privateKey", "peerPublicKey", "presharedKey", "tunnelAddress",
            "allowedIPs", "vkLink", "peerAddress", "useDTLS", "useWrap",
            "wrapKeyHex", "dnsServers", "numConnections"
        ], context: "connection link settings")
    }

    private static func validateCredPoolJSONKeys(_ value: Any) throws {
        guard let pool = value as? [String: Any] else {
            throw BackupError.validationFailed("turn_pool must be an object")
        }
        try validateKeys(pool, allowed: ["version", "saved_at", "creds"], context: "turn_pool")
        guard let entries = pool["creds"] as? [Any] else {
            throw BackupError.validationFailed("turn_pool.creds must be an array")
        }
        if entries.count > maxCredPoolEntries {
            throw BackupError.validationFailed("turn_pool has too many entries")
        }
        for entry in entries {
            try validateNestedKeys(entry, allowed: ["slot", "address", "username", "password", "last_used_at"], context: "turn_pool entry")
        }
    }

    private static func jsonObjectDictionary(_ data: Data, context: String) throws -> [String: Any] {
        do {
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw BackupError.validationFailed("\(context) must be a JSON object")
            }
            return root
        } catch let error as BackupError {
            throw error
        } catch {
            throw BackupError.decodeFailed(error.localizedDescription)
        }
    }

    private static func validateNestedKeys(_ value: Any?, allowed: Set<String>, context: String) throws {
        guard let object = value as? [String: Any] else {
            throw BackupError.validationFailed("\(context) must be an object")
        }
        try validateKeys(object, allowed: allowed, context: context)
    }

    private static func validateKeys(_ object: [String: Any], allowed: Set<String>, context: String) throws {
        let extra = Set(object.keys).subtracting(allowed)
        if let field = extra.sorted().first {
            throw BackupError.validationFailed("unsupported \(context) field '\(field)'")
        }
    }

    private static func validateAppConfig(_ config: AppConfig) throws {
        if config.version != supportedConfigVersion {
            throw BackupError.versionMismatch(config.version)
        }
        switch config.type {
        case settingsOnlyBackupType:
            try validateCommonSettings(config.settings)
        case legacyFullBackupType:
            try validateFullSettings(config.settings)
            if let pool = config.turnPool {
                try validateCredPool(pool)
            }
            if let profile = config.vkProfile {
                try validateVKProfile(profile)
            }
        default:
            throw BackupError.decodeFailed("Unsupported backup type '\(config.type)'")
        }
    }

    private static func validateSafeBackup(_ config: SafeBackupConfig) throws {
        if config.version != supportedConfigVersion {
            throw BackupError.versionMismatch(config.version)
        }
        guard config.type == settingsOnlyBackupType else {
            throw BackupError.decodeFailed("Unsupported backup type '\(config.type)'")
        }
        let settings = AppSettings(
            privateKey: "",
            peerPublicKey: "",
            presharedKey: "",
            tunnelAddress: config.settings.tunnelAddress,
            dnsServers: config.settings.dnsServers,
            allowedIPs: config.settings.allowedIPs,
            vkLink: "",
            peerAddress: "",
            useDTLS: config.settings.useDTLS,
            numConnections: config.settings.numConnections,
            credPoolCooldownSeconds: config.settings.credPoolCooldownSeconds,
            useWrap: config.settings.useWrap,
            wrapKeyHex: nil
        )
        try validateCommonSettings(settings)
    }

    private static func validateConnectionLink(_ link: ConnectionLink) throws {
        if link.version != supportedConfigVersion {
            throw BackupError.versionMismatch(link.version)
        }
        guard link.type == connectionLinkType else {
            throw BackupError.decodeFailed("Expected type=connection, got '\(link.type)'")
        }
        let s = link.settings
        try validateRequiredWireGuardKey(s.privateKey, field: "privateKey")
        try validateRequiredWireGuardKey(s.peerPublicKey, field: "peerPublicKey")
        try validateOptionalWireGuardKey(s.presharedKey, field: "presharedKey")
        try validateTunnelAddress(s.tunnelAddress)
        try validateAllowedIPs(s.allowedIPs)
        try validateVKLink(s.vkLink)
        try validateHostPort(s.peerAddress, field: "peerAddress")
        try validateWrapKey(s.wrapKeyHex, useWrap: s.useWrap)
        if let dns = s.dnsServers {
            try validateDNSServers(dns)
        }
        if let numConnections = s.numConnections {
            try validateRange(numConnections, field: "numConnections", min: 1, max: 50)
        }
    }

    private static func validateCommonSettings(_ s: AppSettings) throws {
        try validateTunnelAddress(s.tunnelAddress)
        try validateDNSServers(s.dnsServers)
        try validateAllowedIPs(s.allowedIPs)
        try validateRange(s.numConnections, field: "numConnections", min: 1, max: 50)
        try validateRange(s.credPoolCooldownSeconds, field: "credPoolCooldownSeconds", min: 0, max: 86_400)
    }

    private static func validateFullSettings(_ s: AppSettings) throws {
        try validateRequiredWireGuardKey(s.privateKey, field: "privateKey")
        try validateRequiredWireGuardKey(s.peerPublicKey, field: "peerPublicKey")
        try validateOptionalWireGuardKey(s.presharedKey, field: "presharedKey")
        try validateVKLink(s.vkLink)
        try validateHostPort(s.peerAddress, field: "peerAddress")
        try validateCommonSettings(s)
        try validateWrapKey(s.wrapKeyHex ?? "", useWrap: s.useWrap ?? false)
    }

    private static func validateCredPool(_ pool: CredCacheFile) throws {
        if pool.version != CredCache.supportedVersion {
            throw BackupError.validationFailed("turn_pool version is not supported")
        }
        if pool.saved_at < 0 {
            throw BackupError.validationFailed("turn_pool saved_at is invalid")
        }
        if pool.creds.count > maxCredPoolEntries {
            throw BackupError.validationFailed("turn_pool has too many entries")
        }
        for entry in pool.creds {
            try validateRange(entry.slot, field: "turn_pool slot", min: 0, max: maxCredPoolEntries - 1)
            try validateHostPort(entry.address, field: "turn_pool address")
            try validateString(entry.username, field: "turn_pool username", minLength: 1, maxLength: maxShortStringLength)
            try validateString(entry.password, field: "turn_pool password", minLength: 1, maxLength: maxShortStringLength)
            if let lastUsed = entry.last_used_at, lastUsed < 0 {
                throw BackupError.validationFailed("turn_pool last_used_at is invalid")
            }
        }
    }

    private static func validateVKProfile(_ entry: VKProfileEntry) throws {
        try validateString(entry.device, field: "vk_profile device", minLength: 1, maxLength: maxVKProfileFieldLength)
        try validateString(entry.browser_fp, field: "vk_profile browser_fp", minLength: 1, maxLength: maxVKProfileFieldLength)
        try validateString(entry.user_agent, field: "vk_profile user_agent", minLength: 1, maxLength: maxShortStringLength)
        if !entry.captured_at.isFinite || entry.captured_at < 0 {
            throw BackupError.validationFailed("vk_profile captured_at is invalid")
        }
    }

    private static func validateRequiredWireGuardKey(_ value: String, field: String) throws {
        try validateString(value, field: field, minLength: 1, maxLength: 128)
        guard decodeWireGuardKey(value) != nil else {
            throw BackupError.validationFailed("\(field) must be a 32-byte Base64 WireGuard key")
        }
    }

    private static func validateOptionalWireGuardKey(_ value: String, field: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return
        }
        try validateRequiredWireGuardKey(trimmed, field: field)
    }

    private static func decodeWireGuardKey(_ value: String) -> Data? {
        var cleaned = value.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padNeeded = (4 - cleaned.count % 4) % 4
        cleaned += String(repeating: "=", count: padNeeded)
        guard let data = Data(base64Encoded: cleaned), data.count == 32 else {
            return nil
        }
        return data
    }

    private static func validateTunnelAddress(_ value: String) throws {
        try validateString(value, field: "tunnelAddress", minLength: 1, maxLength: maxShortStringLength)
        try validateCIDR(value, field: "tunnelAddress", allowIPv6: false)
    }

    private static func validateAllowedIPs(_ value: String) throws {
        try validateString(value, field: "allowedIPs", minLength: 1, maxLength: maxShortStringLength)
        let items = splitCommaSeparated(value)
        if items.isEmpty {
            throw BackupError.validationFailed("allowedIPs must contain at least one CIDR")
        }
        if items.count > maxListItems {
            throw BackupError.validationFailed("allowedIPs has too many entries")
        }
        for item in items {
            try validateCIDR(item, field: "allowedIPs", allowIPv6: true)
        }
    }

    private static func validateDNSServers(_ value: String) throws {
        try validateString(value, field: "dnsServers", minLength: 0, maxLength: maxShortStringLength)
        let items = splitCommaSeparated(value)
        if items.count > maxListItems {
            throw BackupError.validationFailed("dnsServers has too many entries")
        }
        for item in items {
            if !isIPAddress(item) {
                throw BackupError.validationFailed("dnsServers entries must be IP addresses")
            }
        }
    }

    private static func validateCIDR(_ value: String, field: String, allowIPv6: Bool) throws {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]) else {
            throw BackupError.validationFailed("\(field) must use CIDR notation")
        }
        let ip = String(parts[0])
        if isIPv4Address(ip) {
            try validateRange(prefix, field: "\(field) prefix", min: 0, max: 32)
            return
        }
        if allowIPv6 && isIPv6Address(ip) {
            try validateRange(prefix, field: "\(field) prefix", min: 0, max: 128)
            return
        }
        throw BackupError.validationFailed("\(field) contains an invalid IP address")
    }

    private static func validateVKLink(_ value: String) throws {
        try validateString(value, field: "vkLink", minLength: 1, maxLength: maxURLLength)
        guard let components = URLComponents(string: value),
              let scheme = components.scheme?.lowercased(),
              (scheme == "https" || scheme == "http"),
              components.host?.isEmpty == false else {
            throw BackupError.validationFailed("vkLink must be an http(s) URL")
        }
    }

    private static func validateHostPort(_ value: String, field: String) throws {
        try validateString(value, field: field, minLength: 1, maxLength: maxShortStringLength)
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("://") {
            throw BackupError.validationFailed("\(field) must be host:port, not a URL")
        }
        guard let components = URLComponents(string: "turn://\(trimmed)"),
              let host = components.host,
              !host.isEmpty,
              let port = components.port else {
            throw BackupError.validationFailed("\(field) must be host:port")
        }
        try validateString(host, field: "\(field) host", minLength: 1, maxLength: 253)
        try validateRange(port, field: "\(field) port", min: 1, max: 65_535)
    }

    private static func validateWrapKey(_ value: String, useWrap: Bool) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            if useWrap {
                throw BackupError.validationFailed("wrapKeyHex is required when useWrap is true")
            }
            return
        }
        guard trimmed.count == 64,
              trimmed.unicodeScalars.allSatisfy({ hexCharacters.contains($0) }) else {
            throw BackupError.validationFailed("wrapKeyHex must be 64 hex characters")
        }
    }

    private static func validateString(_ value: String, field: String, minLength: Int, maxLength: Int) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.count < minLength {
            throw BackupError.validationFailed("\(field) is empty")
        }
        if trimmed.count > maxLength {
            throw BackupError.validationFailed("\(field) is too long")
        }
        if trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
            throw BackupError.validationFailed("\(field) contains control characters")
        }
    }

    private static func validateRange(_ value: Int, field: String, min: Int, max: Int) throws {
        if value < min || value > max {
            throw BackupError.validationFailed("\(field) must be between \(min) and \(max)")
        }
    }

    private static func splitCommaSeparated(_ value: String) -> [String] {
        value.split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private static func isIPAddress(_ value: String) -> Bool {
        isIPv4Address(value) || isIPv6Address(value)
    }

    private static func isIPv4Address(_ value: String) -> Bool {
        var addr = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &addr) == 1 }
    }

    private static func isIPv6Address(_ value: String) -> Bool {
        var addr = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }
}
