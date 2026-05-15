# Security posture

This fork is intended for private, personal iOS builds first. Do not publish TestFlight, App Store, GitHub Release, IPA, or setup instructions for public users until the audit findings in `docs/audit/ios-security-baseline.md` are addressed.

## Current threat model

- The device may be backed up, inspected through Files/share sheets, or connected to a developer machine.
- Logs may be exported for troubleshooting and shared accidentally.
- Legacy full backups and connection links may contain enough material to recreate VPN access.
- App Group files are shared between the app and PacketTunnel extension and should be treated as local secret storage.
- Apple signing artifacts and App Store Connect credentials are out of scope for the repo and must remain local-only.

## Handling rules

- Do not commit WireGuard private keys, preshared keys, WRAP keys, VK call links, TURN credentials, captured VK browser profiles, provisioning profiles, certificates, `.p12` files, App Store Connect credentials, device UDIDs, or real server IPs unless intentionally documented as examples.
- Do not share exported `vpn.log`, `vpn-export.log`, legacy full backup JSON, or `vkturnproxy://import` links without redaction.
- Treat `creds-pool.json`, `vk_profile.json`, and legacy full backup JSON files as secrets.
- Prefer Keychain for persistent secrets.

## Distribution gate

Public distribution is blocked until:

- secrets are no longer stored in plaintext `UserDefaults` / `AppStorage`;
- plaintext full-secret export is removed, encrypted, or explicitly separated behind a local-only recovery flow;
- full-tunnel mode is no longer a silent default;
- license compatibility with GPL-3.0 `vk-turn-proxy` is resolved.

## Current hardening status

- Redacted logging is implemented for known app, extension, Go, and log-export paths.
- New backup export is settings-only and excludes plaintext secrets.
- Legacy full backup import is still supported for manual recovery, but should be treated as secret input.
- WireGuard private key, preshared key, VK link, and WRAP key are stored in Keychain with legacy `UserDefaults` migration.
- Backup and connection-link imports have size caps plus schema/value validation before apply.
- Fresh installs default to safe routing. Full-device VPN requires an explicit Settings toggle and warning.
- Safe/full routing behavior still requires physical-device validation.
