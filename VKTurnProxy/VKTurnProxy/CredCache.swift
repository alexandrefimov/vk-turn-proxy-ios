// CredCache.swift
//
// Reads creds-pool.json from the App Group container shared with the
// Network Extension. The extension writes this file (see Go-side
// credPool.saveToDisk in pkg/proxy/creds.go) after every successful
// VK cred fetch and after every cred invalidation.
//
// Purpose on the app side: before kicking off a pre-bootstrap captcha
// probe in TunnelManager.connect(), check whether we have a still-valid
// cred cached from a recent session. If yes, use it as the seeded TURN
// cred and skip the entire VK API + captcha round-trip — most of the
// "user reconnected within ~8h" cases never need to talk to VK at all.
//
// The file is intentionally NOT cleaned up on app side. The Go side is
// the only writer; we only read. Stale entries (past their VK-encoded
// expiry) are filtered at read time by parsing the username's
// `<unix_expiry>:<key_id>` prefix per draft-uberti-behave-turn-rest.

import Foundation

/// One persisted slot. Mirrors the Go-side credCacheEntry exactly.
///
/// `last_used_at` is the most recent moment the extension saw a conn
/// holding a TURN allocation against this cred (Unix seconds, 0 = slot
/// was filled but never used — typically the "+1 reserve" slot in the
/// pool). Drives the per-slot saturation check in loadValidCred.
struct CredCacheEntry: Codable {
    let slot: Int
    let address: String
    let username: String
    let password: String
    let last_used_at: Int64?
}

/// On-disk JSON shape. Mirrors the Go-side credCacheFile.
struct CredCacheFile: Codable {
    let version: Int
    let saved_at: Int64
    let creds: [CredCacheEntry]
}

enum CredCache {
    /// Schema version we recognize. Files with a different version are
    /// treated as absent — Go side will rewrite when the extension next
    /// runs, after which the app sees the supported format.
    ///
    /// Bumped to 2 with per-entry last_used_at, replacing a coarser
    /// file-level cooldown that masked the "+1 reserve" slot's
    /// availability after recent disconnects.
    static let supportedVersion = 2

    /// Safety margin before the username-encoded expiry at which we stop
    /// trusting a cached cred. 60s covers the network round-trip the
    /// extension would do to seed slot 0 + open the first DTLS+TURN
    /// session. Independent of the Go-side credExpiryBuffer (30 min) —
    /// app-side has lower stakes (we'd just fall through to captcha if
    /// we picked a too-fresh-but-borderline cred).
    static let expiryGuard: TimeInterval = 60

    /// Per-slot saturation cooldown. VK allocates at most 10 concurrent
    /// TURN allocations per cred set, with each allocation's server-side
    /// lifetime ~600s. When a session ends, pion's Refresh(lifetime=0)
    /// over UDP is best-effort — VK frequently keeps the previous
    /// session's allocations live until they expire. Reusing the same
    /// cred within that window 486s every bootstrap allocation, and the
    /// extension can't recover before iOS kills it on startTunnel
    /// timeout (~17s observed).
    ///
    /// Slots with last_used_at == 0 (background-grower-filled but never
    /// used by any conn) are safe regardless of file age: VK has no
    /// allocations on them. The "+1 reserve" slot is the typical case.
    ///
    /// vpn.wifi.9.log on 2026-05-01 showed the failure mode this fixes:
    /// reconnect 6 minutes after disconnect entered an infinite
    /// preparing → connecting → disconnecting loop because the only
    /// persisted slot was reused with VK's lingering allocations.
    static let saturationCooldown: TimeInterval = 600

    /// App Group container path matching SharedLogger's vpn.log directory
    /// and the Go-side `filepath.Dir(logFilePath) + "/creds-pool.json"`.
    static var cacheURL: URL? {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.vkturnproxy.app"
        )?.appendingPathComponent("creds-pool.json")
    }

    /// Loads the cache and returns the first valid cred (any slot), or
    /// nil if the file is missing, unreadable, version-mismatched, or
    /// every entry is expired/expiring soon.
    ///
    /// Validity check: parses `<unix_expiry>:<key_id>` from username,
    /// requires `expiry - now > 60s`. Malformed usernames are skipped.
    static func loadValidCred() -> (address: String, username: String, password: String)? {
        guard let url = cacheURL else { return nil }
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let f = try? JSONDecoder().decode(CredCacheFile.self, from: data) else {
            return nil
        }
        guard f.version == supportedVersion else { return nil }

        let now = Date().timeIntervalSince1970
        var skipReasons: [String] = []

        for entry in f.creds {
            // Username format per draft-uberti-behave-turn-rest is
            // "<unix_expiry_timestamp>:<key_id>". Anything else means
            // the Go side wrote something we don't recognize — skip
            // rather than crashing on it.
            guard let colonIdx = entry.username.firstIndex(of: ":") else {
                skipReasons.append("slot \(entry.slot) malformed username")
                continue
            }
            let expiryStr = String(entry.username[..<colonIdx])
            guard let expiry = Double(expiryStr) else {
                skipReasons.append("slot \(entry.slot) unparseable expiry")
                continue
            }
            if expiry - now <= expiryGuard {
                skipReasons.append("slot \(entry.slot) expiring in \(Int(expiry - now))s")
                continue
            }

            // Per-slot saturation check. last_used_at == 0 (or absent)
            // means the slot was filled but no conn ever held a TURN
            // allocation on it — typical of the "+1 reserve" slot —
            // and is safe to use regardless of how recent the file is.
            if let lastUsed = entry.last_used_at, lastUsed > 0 {
                let sinceUse = now - TimeInterval(lastUsed)
                if sinceUse >= 0 && sinceUse < saturationCooldown {
                    skipReasons.append("slot \(entry.slot) last used \(Int(sinceUse))s ago")
                    continue
                }
            }

            // First entry that passes all checks wins.
            SharedLogger.shared.log("[AppDebug] CredCache: using slot \(entry.slot) (addr=\(entry.address), expires in \(Int(expiry - now))s, last_used_at=\(entry.last_used_at ?? 0))")
            return (entry.address, entry.username, entry.password)
        }

        if !skipReasons.isEmpty {
            SharedLogger.shared.log("[AppDebug] CredCache: no usable cached cred — skipped: \(skipReasons.joined(separator: ", "))")
        }
        return nil
    }
}
