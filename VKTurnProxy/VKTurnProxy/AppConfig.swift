// AppConfig.swift
//
// Codable representation of app backup/import payloads used by
// BackupManager for the user-facing Export/Import flow in Settings.
//
// Current exports are settings-only and intentionally exclude plaintext
// secrets: WireGuard keys, VK links, WRAP keys, TURN cache, and captured
// browser profile. Legacy "full" backups are still decoded for manual
// restore, but new exports must stay safe-by-default.
//
// Schema version is independent of the on-disk creds-pool.json schema —
// they bump for different reasons. This file's `version` increments when
// the AppConfig wrapper itself changes; CredCacheFile's `version` (which
// we embed verbatim) increments when the TURN-cache shape changes. A
// future v2 of AppConfig might wrap a v3 CredCacheFile, etc.
//
// Connection links remain a separate secret import path. Treat every
// vkturnproxy:// import payload as secret material.

import Foundation

/// Top-level wrapper. `type` is reserved for the future when we add a
/// `connection-only` shareable form alongside `full`.
struct AppConfig: Codable {
    let version: Int
    let type: String
    let exportedAt: Int64
    let settings: AppSettings
    /// Optional because exporters may produce backups before the
    /// extension has ever populated the cache (fresh install with no
    /// prior connect), and importers must tolerate that.
    let turnPool: CredCacheFile?
    /// Captured-from-real-browser PoW solver profile. Optional for the
    /// same reason as turnPool — fresh install + never-solved-captcha
    /// state has nothing to back up. Also Optional so backups exported
    /// before this field shipped still decode (Codable synthesised init
    /// treats absent Optional keys as nil).
    let vkProfile: VKProfileEntry?

    enum CodingKeys: String, CodingKey {
        case version
        case type
        case exportedAt = "exported_at"
        case settings
        case turnPool = "turn_pool"
        case vkProfile = "vk_profile"
    }
}

/// Mirrors every @AppStorage in ContentView.swift / SettingsView. Keep
/// JSON keys identical to the AppStorage keys so a future "edit the
/// backup file in a text editor" workflow has obvious field names.
///
/// Newer fields (added after the v1 schema shipped) are declared
/// Optional so loading an older backup that doesn't contain them
/// still decodes — Codable's synthesised init treats absent Optional
/// keys as nil. The corresponding apply step in BackupManager uses
/// the AppStorage default when nil. Each addition documents which
/// build introduced it for traceability.
struct AppSettings: Codable {
    let privateKey: String
    let peerPublicKey: String
    let presharedKey: String
    let tunnelAddress: String
    let dnsServers: String
    let allowedIPs: String
    let vkLink: String
    let peerAddress: String
    let useDTLS: Bool
    let numConnections: Int
    let credPoolCooldownSeconds: Int
    /// WRAP layer (ChaCha20-XOR ChannelData payload obfuscation, see
    /// vk-turn-proxy-ios commit 1c1edc1 / branch add-client-wrap-layer).
    /// Optional for back-compat with backups exported before WRAP shipped.
    let useWrap: Bool?
    /// 64-character hex encoding of the 32-byte WRAP shared key. Must
    /// match the server's -wrap-key. Optional for back-compat.
    let wrapKeyHex: String?
}

// MARK: - Safe Settings Backup

/// Exported by the Backup & Restore UI. Contains only non-secret local
/// preferences, so the resulting JSON can be shared without exposing tunnel
/// credentials. Importing this payload must not overwrite existing secrets.
struct SafeBackupConfig: Codable {
    let version: Int
    let type: String
    let exportedAt: Int64
    let settings: SafeBackupSettings

    enum CodingKeys: String, CodingKey {
        case version
        case type
        case exportedAt = "exported_at"
        case settings
    }
}

struct SafeBackupSettings: Codable {
    let tunnelAddress: String
    let dnsServers: String
    let allowedIPs: String
    let useDTLS: Bool
    let numConnections: Int
    let credPoolCooldownSeconds: Int
    let useWrap: Bool

    enum CodingKeys: String, CodingKey {
        case tunnelAddress
        case dnsServers
        case allowedIPs
        case useDTLS
        case numConnections
        case credPoolCooldownSeconds
        case useWrap
    }
}

// MARK: - 1-Click Connection Link
//
// Lightweight payload sibling to AppConfig used for the 1-Click import
// feature. Encoded as base64 inside `vkturnproxy://import?data=…` URLs
// (or raw on the clipboard) so a server admin can hand a fresh device
// the entire deployment definition in one tap.
//
// Deliberately a SEPARATE struct from AppConfig/AppSettings — does NOT
// reuse them — so that:
//   • Connection links don't accidentally leak the TURN credential cache
//     or the captured browser profile (those belong to the device, not
//     the deployment).
//   • Field requirements differ from full backups: dnsServers and
//     numConnections are optional in a link (the receiving device keeps
//     its current value if absent), whereas in a full backup they're
//     always present. credPoolCooldownSeconds is excluded entirely from
//     links — it's an internal tuning knob nobody should override at
//     onboarding time.
//
// Schema version is shared with AppConfig (BackupManager.supportedConfigVersion)
// so a new schema version invalidates BOTH backup files and connection
// links uniformly.

struct ConnectionLink: Codable {
    let version: Int
    /// Always "connection" for link payloads. Distinguishes from
    /// AppConfig's "full" so the parser can early-reject mismatched
    /// inputs (e.g. user accidentally pastes a full-backup base64 here).
    let type: String
    let settings: ConnectionSettings
}

/// Subset of AppSettings that defines a deployment. WG keys + server
/// address + vkLink + WRAP key are all required; per-device tunables
/// (dnsServers, numConnections) are optional.
struct ConnectionSettings: Codable {
    let privateKey: String
    let peerPublicKey: String
    let presharedKey: String
    let tunnelAddress: String
    let allowedIPs: String
    let vkLink: String
    let peerAddress: String
    let useDTLS: Bool
    let useWrap: Bool
    let wrapKeyHex: String
    /// Optional: if absent, the importing device keeps its current
    /// dnsServers value (or the AppStorage default of "1.1.1.1" if
    /// never set). Always set on apply when present.
    let dnsServers: String?
    /// Optional: if absent, the importing device keeps its current
    /// numConnections (default 30). Useful for an admin to ship a
    /// "recommended for this deployment" hint while still letting
    /// users tune later.
    let numConnections: Int?
}
