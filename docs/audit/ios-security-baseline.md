# iOS security baseline

## Summary

This repo is buildable in principle as a private iOS Network Extension client, but this environment cannot validate the iOS build: `go` is not installed, and `xcodebuild` reports Command Line Tools instead of full Xcode. The highest priority fixes are secret handling and log redaction before any public distribution work.

Main risks:

- Critical: WireGuard private key, preshared key, VK link, WRAP key, and TURN credentials are stored in plaintext `@AppStorage` / `UserDefaults` and full backup JSON.
- Critical: PacketTunnel logs the full `proxy_config`, which includes `vk_link`, `wrap_key_hex`, and seeded TURN username/password.
- High: log export shares raw combined logs with no redaction.
- High: full-tunnel mode is enabled silently with `includeAllNetworks = true` and default `allowedIPs = 0.0.0.0/0`.
- High: import/link parsing has version checks but no explicit payload size limits or full schema/value validation.
- High: license compatibility is unresolved for public distribution because this repo says MIT while the Go module and README identify GPL-3.0 upstream ancestry through `vk-turn-proxy`.

Recommended first patch: add a redacted logging helper and route all app/extension/Go bridge messages that can contain config or URLs through it. Do not change tunnel behavior in that patch.

## Repository map

- `VKTurnProxy/` - iOS project, Xcode project, generated/declared plist files, app target, PacketTunnel extension, and export plists.
- `VKTurnProxy/VKTurnProxy/` - SwiftUI app target. Important files: `ContentView.swift`, `TunnelManager.swift`, `BackupManager.swift`, `AppConfig.swift`, `SharedLogger.swift`, `CredCache.swift`, `VKProfileCache.swift`, `OSLogReader.swift`, `VKTurnProxyApp.swift`.
- `VKTurnProxy/PacketTunnel/` - Network Extension target. Important files: `PacketTunnelProvider.swift`, `PacketTunnel.entitlements`, `Info.plist`, `BridgeHeader.h`.
- `WireGuardBridge/` - Go to C bridge and XCFramework build. Important files: `bridge.go`, `Makefile`, `include/wireguard_turn.h`, patched Go runtime diff.
- `pkg/proxy/` - Go proxy code for VK credential fetch, captcha PoW/slider solver, TURN/DTLS, WRAP, watchdog and path handling.
- `pkg/turnbind/` - WireGuard bind implementation that routes packets through the proxy.
- `tools/turn_bw_*` - local TURN bandwidth tooling that consumes exported backup JSON.
- `quick_link.py` - generates secret-bearing `vkturnproxy://import` links.
- `release.sh` - public release/TestFlight pipeline; not appropriate for private hardening work before security fixes.

## Sensitive data inventory

| File | Data | Sensitivity | Recommendation |
| --- | --- | --- | --- |
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | `@AppStorage` for `privateKey`, `presharedKey`, `vkLink`, `wrapKeyHex`, `peerAddress`, `allowedIPs`, `dnsServers`, `numConnections`, `credPoolCooldownSeconds` | critical for keys/link/wrap; medium for routes/tuning | Move secrets to Keychain. Leave only UI preferences in `UserDefaults` / `AppStorage`. |
| `VKTurnProxy/VKTurnProxy/BackupManager.swift` | Reads/writes all secret settings via `UserDefaults.standard`; exports/imports `creds-pool.json`; restores `vk_profile.json` | critical | Disable plaintext secret export or split into non-secret export plus explicit encrypted/local recovery flow. Add size and schema validation before decode/apply. |
| `VKTurnProxy/VKTurnProxy/AppConfig.swift` | `AppConfig`, `AppSettings`, `ConnectionLink`, `ConnectionSettings` include WireGuard keys, VK link, WRAP key, TURN pool and browser profile | critical | Mark all links/backups as secret. Add validation model separate from persisted model. |
| `VKTurnProxy/VKTurnProxy/CredCache.swift` | Reads App Group `creds-pool.json` with TURN `address`, `username`, `password` | critical | Keep out of backups by default; consider file protection and Keychain-backed cache later. |
| `VKTurnProxy/VKTurnProxy/VKProfileCache.swift` | App Group `vk_profile.json`: captured `device`, `browser_fp`, `user_agent` | high | Treat as secret telemetry/fingerprint. Keep out of logs and plaintext backups by default. |
| `VKTurnProxy/VKTurnProxy/SharedLogger.swift` | App Group `vpn.log` and `vpn.log.1`, temp `vpn-export.log` | high | Add central redaction before write and before export. Consider file protection. |
| `VKTurnProxy/VKTurnProxy/OSLogReader.swift` | Reads recent app/extension `os_log` fallback | high | Redact fallback output before display/export. |
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | `UIPasteboard.general.string` import of connection link | critical | Treat clipboard payload as secret; add length limit and validation before base64 decode. |
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | Logs UI share sheet exports raw log file/fallback | high | Export only redacted snapshot. Add warning that logs can contain secrets until fixed. |
| `VKTurnProxy/VKTurnProxy/TunnelManager.swift` | Builds WireGuard UAPI config containing `private_key` and optional `preshared_key` | critical | Never log UAPI config. Keep generation local to connect path. |
| `VKTurnProxy/VKTurnProxy/TunnelManager.swift` | Builds `proxy_config` with `vk_link`, `wrap_key_hex`, seeded TURN username/password | critical | Do not log full JSON. Redact before any diagnostic output. |
| `VKTurnProxy/PacketTunnel/PacketTunnelProvider.swift` | Reads provider `wg_config` and `proxy_config` | critical | Do not log full configs. Replace current `proxyConfig=` log. |
| `WireGuardBridge/bridge.go` | Parses `ProxyConfig`, `SeededTURN`, `WrapKeyHex`; logs errors and addresses | high | Avoid logging secret JSON/errors that echo values. Keep logging lengths/status only. |
| `pkg/proxy/creds.go` | Hardcoded VK app client IDs/secrets and runtime TURN credentials | medium/high | Do not print secret values. Confirm whether embedded VK client secrets are acceptable for private build. |
| `pkg/proxy/creds.go` | Logs captcha URLs, captcha SID, TURN relay addresses, VK identity UA/name | high | Redact captcha URLs/SIDs and minimize identity/fingerprint logging. |
| `pkg/proxy/captcha_pow.go` | Logs PoW internals, HTML preview, adFp ID, browser profile usage metadata | medium/high | Ensure no full browser profile, cookie, token, or HTML with token is emitted. |
| `quick_link.py` | Generates links containing private key, PSK, VK link, peer address, WRAP key | critical | Do not store generated JSON/link in repo. Consider reading from password manager/local ignored file only. |
| `VKTurnProxy/ExportOptions*.plist` | Tracked export options with team ID and distribution mode | low/medium | Keep future local variants ignored. Consider templating tracked files later if public fork hygiene matters. |

No Keychain usage was found.

## Network Extension behavior

- `NETunnelProviderProtocol` is created in `VKTurnProxy/VKTurnProxy/TunnelManager.swift`.
- `providerBundleIdentifier` is `com.vkturnproxy.app.tunnel`.
- `providerConfiguration` carries `wg_config`, `proxy_config`, `tunnel_address`, `dns_servers`, and `mtu`.
- `includeAllNetworks = true` is set unconditionally.
- `excludeLocalNetworks = true` is set unconditionally.
- On iOS 16.4+, `excludeAPNs = false` and `excludeCellularServices = false` are set to force those services into the tunnel.
- `PacketTunnelProvider.createTunnelSettings` sets IPv4 `includedRoutes` to default route by default and `excludedRoutes = []`.
- DNS settings come from comma-separated `dnsServers`, default `1.1.1.1`.
- MTU is read from provider config, default `1280`, and applied if it parses as an integer.
- `allowedIPs` from UI/defaults are converted into WireGuard UAPI `allowed_ip=` lines; default is `0.0.0.0/0`.
- WiFi/LTE handoff handling exists in `PacketTunnelProvider.swift` through `NWPathMonitor`, `wgPathChanged`, `wgPathInTransition`, wake health checks, and Go watchdog logic.
- Full tunnel is effectively default because `allowedIPs` defaults to `0.0.0.0/0` and `includeAllNetworks` is unconditional. This conflicts with the hardening rule that full tunnel must not be the silent default.

## Logging audit

Logging surfaces:

- `SharedLogger.shared.log` writes plaintext to App Group `vpn.log`.
- `os_log("%{public}s", ...)` and `NSLog` duplicate some messages to system logs.
- `OSLogReader.readOwnLogs` reads recent in-process logs as fallback.
- `LogsView` displays logs and exports a temp log file through share sheet.
- Go logs are routed through `wgSetLogFilePath` into the same App Group log and through `os_log`.

Findings:

- Critical: `PacketTunnelProvider.swift` logs `proxyConfig=\(proxyConfigJSON)`, which can contain `vk_link`, `wrap_key_hex`, and `seeded_turn.password`.
- WireGuard UAPI config is not directly logged in the observed Swift path, but Go `IpcSet` error strings could potentially include config context depending on upstream error behavior.
- Go proxy logs captcha URLs/SIDs, TURN relay addresses, path data, and diagnostic HTTP snippets. It appears to log lengths for captcha answers/tokens rather than full tokens, but a redaction pass is still required.
- `applyConnectionLink` comments say vkLink should be truncated, but the actual log includes full `peerAddress` and no vkLink. Peer/server address should still be treated as sensitive for a private fork.
- `VKProfileCache` logs profile field lengths, not raw profile values.
- `SharedLogger.exportSnapshotURL` and `LogsView.exportShareableLogURL` export raw log text with no redaction.

## Backup/import/export audit

- Full backup export writes pretty JSON to app temp as `vkturnproxy-backup-<timestamp>.json` and sends it to the share sheet.
- Full backup includes all `AppStorage` settings, optional TURN `turn_pool`, and optional `vk_profile`.
- The UI warns that backup contains WireGuard keys, TURN credentials, and captured browser profile, but the file is plaintext.
- Full backup import accepts `.json`, `.text`, `.data`, and `.item`, then reads the selected file fully into memory and decodes as `AppConfig`.
- Connection links are accepted from `vkturnproxy://import?data=...` or raw clipboard base64.
- `parseConnectionLinkBase64` normalizes base64 and decodes without explicit input size limit.
- Version and `type == "connection"` checks exist.
- Missing: explicit schema validation for key lengths, allowed CIDRs, DNS/IP/host formats, `numConnections` bounds, `mtu` bounds, and oversized/malicious payload rejection before decode.

## Build/signing audit

- Bundle IDs in `VKTurnProxy/project.yml`: `com.vkturnproxy.app` and `com.vkturnproxy.app.tunnel`.
- `DEVELOPMENT_TEAM` is set to `CDMQ33VFQC`; `CODE_SIGN_STYLE` is Automatic.
- Both app and extension entitlements include `packet-tunnel-provider`, `wifi-info`, and App Group `group.com.vkturnproxy.app`.
- The app declares custom URL scheme `vkturnproxy`.
- The extension `Info.plist` declares `com.apple.networkextension.packet-tunnel`.
- `WireGuardBridge/Makefile` requires Go, Xcode SDKs, clang, and `xcodebuild -create-xcframework`.
- `.gitignore` now covers future Apple signing/private files: `.p12`, provisioning profiles, `ExportOptions*.plist`, archives, and env files.
- Existing `VKTurnProxy/ExportOptions.plist` and `VKTurnProxy/ExportOptionsLocal.plist` are already tracked and contain team ID / export method metadata. They are not private keys, but public release assumptions should be removed or templated in a later cleanup.
- `release.sh` is a public TestFlight/GitHub Release pipeline and should not be used for this private hardening phase.

## License risk

- Local `README.md` says `MIT`.
- No root `LICENSE` file was found.
- `go.mod` declares module `github.com/cacggghp/vk-turn-proxy`, and README credits that upstream project.
- The task context states upstream `vk-turn-proxy` is GPL-3.0. Treat compatibility between this repo's MIT claim and GPL-3.0-derived code as unresolved.
- Private local build/testing is lower risk, but public TestFlight/App Store/GitHub distribution should be blocked until license obligations are reviewed and documented.

## Phase 1 hardening plan

1. Redacted logging helper: add a small Swift redactor plus Go-side equivalent for known key names, URLs, TURN credentials, WRAP keys, VK links, browser profile fields, and WireGuard UAPI keys. Replace the `proxyConfig=` log first.
2. Disable plaintext secret export: split export into non-secret settings export, or gate full backup behind an explicit local-only warning until encrypted backup exists.
3. KeychainStore for secrets: move `privateKey`, `presharedKey`, `vkLink`, `wrapKeyHex`, and possibly `peerAddress` to Keychain. Leave `dnsServers`, UI toggles, and non-sensitive tuning in `AppStorage`.
4. Safe/split mode default: default to non-full-tunnel routing for fresh installs.
5. Full-tunnel explicit toggle/warning: require user action before `includeAllNetworks = true` and `allowedIPs = 0.0.0.0/0`.
6. Safer defaults for `numConnections`/MTU: lower initial `numConnections`, validate import bounds, and enforce MTU range.
7. Import schema validation: cap file/link size, validate keys/base64, CIDRs, DNS, host:port, URL scheme/host, booleans, and numeric bounds before applying.
8. Reset all secrets button: clear Keychain secrets, UserDefaults non-sensitive config, TURN cache, browser profile, logs, and Network Extension preferences.

## Validation commands

Commands run in this environment:

```bash
pwd
git status --short
git branch --show-current
git remote -v
git log --oneline -10
find . -maxdepth 3 -type f | sort | sed 's#^\./##' | head -300
rg -n '@AppStorage|UserDefaults|suiteName|Keychain|UIPasteboard|clipboard|export|import|Backup|FileManager|os_log|OSLog|Logger|print\(|SharedLogger|privateKey|preshared|psk|vkLink|TURN|turn|wrap|WRAP|browser_fp|browser|device|captcha|includeAllNetworks|excludeLocalNetworks|includedRoutes|excludedRoutes|allowedIPs|dnsSettings|mtu|MTU|NEPacketTunnel|NETunnel|handoff|pathUpdate|WiFi|LTE|cellular'
plutil -p VKTurnProxy/VKTurnProxy/VKTurnProxy.entitlements
plutil -p VKTurnProxy/PacketTunnel/PacketTunnel.entitlements
plutil -p VKTurnProxy/VKTurnProxy/Info.plist
plutil -p VKTurnProxy/PacketTunnel/Info.plist
go test ./...
xcodebuild -version
```

Validation result:

- Static file inspection completed.
- `plutil` inspection completed.
- `go test ./...` did not run because `go` is not installed in this environment.
- Xcode build did not run because active developer directory is Command Line Tools, not full Xcode.
- No device validation was performed.

Local validation required on a Mac with full toolchain:

```bash
cd WireGuardBridge
make xcframework
cd ../VKTurnProxy
xcodebuild -project VKTurnProxy.xcodeproj -scheme VKTurnProxy -destination 'generic/platform=iOS' -configuration Debug build
```

For actual Network Extension validation, use Xcode with a physical iOS device, a paid Apple Developer account, matching App Group IDs, and the Network Extension entitlement. Do not claim tunnel validation until the device run confirms connect, disconnect, captcha fallback, log view, WiFi/LTE handoff, and import/export behavior.
