# VK TURN Proxy — iOS

Private iOS client fork for [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) — a WireGuard VPN tunnel that routes traffic through VK's TURN infrastructure.

This fork is currently in private hardening mode. Security fixes and reproducible local builds take priority over features and public distribution.

## Features

- Native iOS app with Network Extension (PacketTunnelProvider)
- Go-based WireGuard + DTLS/TURN proxy compiled as XCFramework
- Automatic VK Smart Captcha solving (SHA-256 Proof-of-Work)
- WebView fallback for captcha when PoW is rejected
- Self-healing tunnel: survives iOS sleep/wake, WiFi↔LTE handoff
- Watchdog-based dead tunnel detection (no reliance on iOS `sleep()`/`wake()` callbacks)
- Staggered reconnection to avoid TURN Allocation Quota errors
- Randomized identity (User-Agent + Russian names) per credential fetch

## Project Structure

```
VKTurnProxy/          # iOS app (SwiftUI) + PacketTunnel extension
WireGuardBridge/      # Go → C bridge, builds XCFramework via Makefile
pkg/proxy/            # Go proxy: DTLS+TURN tunnel, VK creds, PoW captcha solver
go.mod, go.sum        # Go module dependencies
```

## Distribution status

Public TestFlight, App Store, and GitHub Release distribution are blocked until the security audit items are closed. Build only for personal testing on a physical iPhone.

## Building

See [docs/build/ios-local-build.md](docs/build/ios-local-build.md) for the private local-device workflow.

Minimum prerequisites:

- Full Xcode 15+ selected with `xcode-select`.
- Go 1.21+.
- XcodeGen.
- Apple Developer Program account with Network Extension capability.
- App Group configured for the app and PacketTunnel extension.
- Physical iPhone. Simulator is not sufficient for PacketTunnel validation.

## Documentation

- [Security posture](SECURITY.md)
- [Baseline iOS security audit](docs/audit/ios-security-baseline.md)
- [Redaction notes](docs/audit/redaction-notes.md)
- [Toolchain and environment](docs/dev/toolchain.md)
- [Private local iPhone build](docs/build/ios-local-build.md)

## Configuration

In the app's Settings screen, configure:

- **WireGuard Config** — standard WireGuard config (Interface + Peer)
- **VK Link** — VK call invite link (e.g., `https://vk.com/call/join/...`)
- **Proxy Config** — JSON with `peer_addr`, connection count, DTLS/UDP options

## Credits

Based on [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) by [cacggghp](https://github.com/cacggghp).

## License

This repository currently states MIT, but it is based on `vk-turn-proxy`, which is treated as a GPL-3.0 compatibility risk for public distribution. Private local testing can continue while license compatibility is reviewed.
