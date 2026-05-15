# Redaction notes

## Scope

Phase 1 redacts diagnostic logs only. It does not change VPN routing, WireGuard settings, import/export semantics, storage, Network Extension preferences, or Go proxy behavior.

## Covered paths

- Swift `SharedLogger.log` and `SharedLogger.logRaw` redact before writing to `vpn.log`.
- `SharedLogger.readLogs` returns redacted text, so in-app display and normal share export do not expose older unsafe lines already present on disk.
- PacketTunnel `logMsg` redacts before `os_log`, `NSLog`, and shared file logging.
- Captcha WebView debug logging redacts before `os_log`, `NSLog`, and the app-to-extension debug log path.
- Go `log.Printf` output is redacted in `osLogWriter` before both iOS `os_log` and the async file writer.

## Redacted classes

- WireGuard private and preshared keys.
- VK call/import links.
- WRAP keys.
- TURN username/password and seeded TURN credentials.
- Captured browser profile fields (`browser_fp`, `device`).
- Captcha/session/access/success tokens and common `token`, `sid`, `hash`, `key`, `auth`, `signature`, `sign` query parameters.
- 64-character hex strings.

## Residual risk

This is a pattern-based redactor. It reduces known leaks but is not a substitute for removing plaintext secret storage and plaintext backup export in later phases.
