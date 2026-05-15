# iOS security baseline

## Summary

This repo now passes local static checks, Go package checks, WireGuardBridge XCFramework build, and compile-only Xcode build without signing. The highest priority remaining fix is safe/split mode defaults before any public distribution work.

Main risks:

- Mitigated in `main`: WireGuard private key, preshared key, VK link, and WRAP key are stored in Keychain and legacy `UserDefaults` values are migrated/cleared.
- Mitigated in `hardening/redacted-logs`: PacketTunnel no longer logs full `proxy_config`, and known app/extension/Go log/export paths are pattern-redacted.
- Mitigated in `hardening/no-plaintext-backup`: new backup export is settings-only and excludes keys, links, WRAP key, TURN credentials, and captured browser profile.
- Mitigated in `main`: backup and connection-link import paths have size caps, schema checks, and value validation before apply.
- High: full-tunnel mode is enabled silently with `includeAllNetworks = true` and default `allowedIPs = 0.0.0.0/0`.
- High: license compatibility is unresolved for public distribution because this repo says MIT while the Go module and README identify GPL-3.0 upstream ancestry through `vk-turn-proxy`.

Recommended next patch: safe/split mode default with an explicit full-tunnel toggle/warning.

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
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | `@AppStorage` for non-secret settings; Keychain-backed state for `privateKey`, `presharedKey`, `vkLink`, `wrapKeyHex` | high | Keep secret fields out of `@AppStorage`. Add device validation for Keychain migration path. |
| `VKTurnProxy/VKTurnProxy/KeychainStore.swift` | Generic-password Keychain items for private key, PSK, VK link, WRAP key | high | Uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; verify on physical iPhone after install/update. |
| `VKTurnProxy/VKTurnProxy/BackupManager.swift` | New export writes settings-only backup; legacy full import can still apply plaintext secrets into Keychain from user-selected files | high | Keep export safe. Size/schema/value validation is in place; consider explicit warning for legacy full import. |
| `VKTurnProxy/VKTurnProxy/AppConfig.swift` | `AppConfig`, `AppSettings`, `ConnectionLink`, `ConnectionSettings` include WireGuard keys, VK link, WRAP key, TURN pool and browser profile | critical | Mark all links/backups as secret. Add validation model separate from persisted model. |
| `VKTurnProxy/VKTurnProxy/CredCache.swift` | Reads App Group `creds-pool.json` with TURN `address`, `username`, `password` | critical | Keep out of backups by default; consider file protection and Keychain-backed cache later. |
| `VKTurnProxy/VKTurnProxy/VKProfileCache.swift` | App Group `vk_profile.json`: captured `device`, `browser_fp`, `user_agent` | high | Treat as secret telemetry/fingerprint. Keep out of logs and plaintext backups by default. |
| `VKTurnProxy/VKTurnProxy/SharedLogger.swift` | App Group `vpn.log` and `vpn.log.1`, temp `vpn-export.log` | high | Keep central redaction before write and before export. Consider file protection. |
| `VKTurnProxy/VKTurnProxy/OSLogReader.swift` | Reads recent app/extension `os_log` fallback | high | Keep fallback output redacted before display/export. |
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | `UIPasteboard.general.string` import of connection link | critical | Treat clipboard payload as secret; add length limit and validation before base64 decode. |
| `VKTurnProxy/VKTurnProxy/ContentView.swift` | Logs UI share sheet exports log file/fallback | high | Keep export path using a redacted snapshot. |
| `VKTurnProxy/VKTurnProxy/TunnelManager.swift` | Builds WireGuard UAPI config containing `private_key` and optional `preshared_key` | critical | Never log UAPI config. Keep generation local to connect path. |
| `VKTurnProxy/VKTurnProxy/TunnelManager.swift` | Builds `proxy_config` with `vk_link`, `wrap_key_hex`, seeded TURN username/password | critical | Do not log full JSON. Redact before any diagnostic output. |
| `VKTurnProxy/VKTurnProxy/TunnelManager.swift` | Passes generated `wg_config` and `proxy_config` through `NETunnelProviderProtocol.providerConfiguration` for PacketTunnel startup | critical | Treat Network Extension preferences as secret-bearing until a safer extension handoff is designed and physical-device tested. |
| `VKTurnProxy/PacketTunnel/PacketTunnelProvider.swift` | Reads provider `wg_config` and `proxy_config` | critical | Do not log full configs; keep provider-config logs structural/status-only. |
| `WireGuardBridge/bridge.go` | Parses `ProxyConfig`, `SeededTURN`, `WrapKeyHex`; logs errors and addresses | high | Avoid logging secret JSON/errors that echo values. Keep logging lengths/status only. |
| `pkg/proxy/creds.go` | Hardcoded VK app client IDs/secrets and runtime TURN credentials | medium/high | Do not print secret values. Confirm whether embedded VK client secrets are acceptable for private build. |
| `pkg/proxy/creds.go` | Logs captcha URLs, captcha SID, TURN relay addresses, VK identity UA/name | high | Redact captcha URLs/SIDs and minimize identity/fingerprint logging. |
| `pkg/proxy/captcha_pow.go` | Logs PoW internals, HTML preview, adFp ID, browser profile usage metadata | medium/high | Ensure no full browser profile, cookie, token, or HTML with token is emitted. |
| `quick_link.py` | Generates links containing private key, PSK, VK link, peer address, WRAP key | critical | Do not store generated JSON/link in repo. Consider reading from password manager/local ignored file only. |
| `VKTurnProxy/ExportOptions*.plist` | Tracked export options with team ID and distribution mode | low/medium | Keep future local variants ignored. Consider templating tracked files later if public fork hygiene matters. |

Keychain is now used for `privateKey`, `presharedKey`, `vkLink`, and `wrapKeyHex`.

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

- Mitigated: `PacketTunnelProvider.swift` logs only redacted `proxyConfig` metadata after `hardening/redacted-logs`.
- WireGuard UAPI config is not directly logged in the observed Swift path, but Go `IpcSet` error strings could potentially include config context depending on upstream error behavior.
- Go proxy logs pass through a pattern redactor before shared file logging and `os_log`. Residual risk remains because the redactor is pattern-based.
- `applyConnectionLink` comments say vkLink should be truncated, but the actual log includes full `peerAddress` and no vkLink. Peer/server address should still be treated as sensitive for a private fork.
- `VKProfileCache` logs profile field lengths, not raw profile values.
- `SharedLogger.exportSnapshotURL` and `LogsView.exportShareableLogURL` now export redacted text. Older unsafe lines may still exist on disk until logs are cleared, but read/export paths redact them.

## Backup/import/export audit

- Safe backup export writes pretty JSON to app temp as `vkturnproxy-settings-backup-<timestamp>.json` and sends it to the share sheet.
- Safe backup includes only non-secret preferences: tunnel address, DNS, allowed IPs, DTLS/WRAP toggles, connection count, and cooldown.
- Safe backup excludes WireGuard private key, preshared key, peer public key, VK link, peer address, WRAP key, TURN `turn_pool`, and `vk_profile`.
- Legacy full backup import is still accepted for manual recovery, but new exports no longer create that format.
- Full backup import accepts `.json`, `.text`, `.data`, and `.item`, then enforces a file-size cap before reading and decoding as `AppConfig`.
- Connection links are accepted from `vkturnproxy://import?data=...` or raw clipboard base64.
- Backup and connection-link imports reject oversized payloads before decode/apply.
- Decoded import payloads validate known schema keys, WireGuard key shape, allowed CIDRs, DNS/IP values, `host:port` fields, WRAP key shape, `numConnections`, cooldowns, TURN cache entry count, and captured profile field lengths.

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

1. Done: redacted logging helper for known key names, URLs, TURN credentials, WRAP keys, VK links, browser profile fields, and WireGuard UAPI keys.
2. Done: plaintext secret export removed. New export uses settings-only `SafeBackupConfig`; legacy full import remains for manual recovery.
3. Done: KeychainStore for `privateKey`, `presharedKey`, `vkLink`, and `wrapKeyHex`; non-sensitive tuning remains in `AppStorage`.
4. Safe/split mode default: default to non-full-tunnel routing for fresh installs.
5. Full-tunnel explicit toggle/warning: require user action before `includeAllNetworks = true` and `allowedIPs = 0.0.0.0/0`.
6. Safer defaults for `numConnections`/MTU: lower initial `numConnections` and enforce MTU range.
7. Done: import schema validation caps file/link size and validates JSON version/type/known fields, key lengths, CIDRs, host:port, DNS, WRAP key, and `numConnections` bounds before applying.
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
cd WireGuardBridge
GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go go test .
xcodebuild -version
```

Validation result:

- Static file inspection completed.
- `plutil` inspection completed.
- `go test .` passes for `WireGuardBridge` after installing Go and using writable temp Go cache paths.
- Do not use `go test ./...` from `WireGuardBridge` after `make xcframework`: the ignored `build/goroot` staging tree is under the module directory and makes Go walk copied runtime test fixtures.
- Active Xcode is `/Applications/Xcode.app/Contents/Developer`; `xcodebuild -version` reports Xcode 26.4.1.
- `make -C WireGuardBridge xcframework` completes with the selected full Xcode and iPhoneOS SDK.
- Compile-only `xcodebuild` for `VKTurnProxy` with `CODE_SIGNING_ALLOWED=NO` completes under `iphoneos`; signed device validation still requires Apple provisioning and a physical iPhone.
- No device validation was performed.

Local validation required on a Mac with full toolchain:

```bash
cd WireGuardBridge
GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go make xcframework
cd ../VKTurnProxy
xcodebuild -project VKTurnProxy.xcodeproj -scheme VKTurnProxy -configuration Debug -sdk iphoneos -derivedDataPath /private/tmp/vk-turn-derived-data CODE_SIGNING_ALLOWED=NO build
```

For actual Network Extension validation, use Xcode with a physical iOS device, a paid Apple Developer account, matching App Group IDs, and the Network Extension entitlement. Do not claim tunnel validation until the device run confirms connect, disconnect, captcha fallback, log view, WiFi/LTE handoff, and import/export behavior.
