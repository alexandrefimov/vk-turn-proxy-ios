// AppConfig.swift
//
// Codable representation of the entire app's persisted state, used by
// BackupManager for the user-facing Export/Import flow in Settings.
//
// Two scopes of "state" the user might want to preserve:
//   1. UserDefaults-backed @AppStorage values (connection params,
//      WireGuard keys, tuning knobs).
//   2. The TURN credential cache the extension writes to the App Group
//      container (creds-pool.json). Including this in the backup means
//      a restore can skip the VK PoW + captcha round on first connect
//      after import — directly relevant when migrating to a fresh install
//      after `xcrun devicectl install` left the previous cache behind.
//
// Schema version is independent of the on-disk creds-pool.json schema —
// they bump for different reasons. This file's `version` increments when
// the AppConfig wrapper itself changes; CredCacheFile's `version` (which
// we embed verbatim) increments when the TURN-cache shape changes. A
// future v2 of AppConfig might wrap a v3 CredCacheFile, etc.
//
// Sensitive content: WireGuard private key, preshared key, and TURN
// credentials are all in plaintext here. The app warns the user before
// share — no encryption in this iteration. Friend-shareable subsets
// (without TURN cache) are a separate "connection link" feature planned
// for a follow-up.

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

    enum CodingKeys: String, CodingKey {
        case version
        case type
        case exportedAt = "exported_at"
        case settings
        case turnPool = "turn_pool"
    }
}

/// Mirrors every @AppStorage in ContentView.swift / SettingsView. Keep
/// JSON keys identical to the AppStorage keys so a future "edit the
/// backup file in a text editor" workflow has obvious field names.
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
}
