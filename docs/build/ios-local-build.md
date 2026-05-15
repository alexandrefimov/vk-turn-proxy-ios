# Private local iPhone build

## Goal

Build and install a private development build on a physical iPhone without public TestFlight, App Store, or GitHub Release distribution.

## Prerequisites

- Full Xcode 15 or newer installed from Apple.
- Xcode selected with `xcode-select`.
- Go installed.
- XcodeGen installed.
- Apple Developer Program account.
- App ID for the main app with:
  - Network Extension capability.
  - App Groups capability.
- App ID for the PacketTunnel extension with:
  - Network Extension capability.
  - App Groups capability.
- Shared App Group matching the project entitlement value.
- Physical iPhone trusted by the Mac.

## Select full Xcode

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -runFirstLaunch
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
```

`xcrun --sdk iphoneos --show-sdk-path` must print an SDK path. If it fails, the Go XCFramework cannot be built.

## Install CLI dependencies

```bash
brew install go xcodegen
```

## Generate or verify the Xcode project

Only regenerate when `VKTurnProxy/project.yml` changed:

```bash
cd VKTurnProxy
xcodegen generate
```

Return to repo root before the next steps.

## Build the Go XCFramework

```bash
cd WireGuardBridge
make xcframework
```

Expected output:

```text
WireGuardBridge/build/WireGuardTURN.xcframework
```

If Go cache permissions fail in a sandboxed shell, use:

```bash
GOCACHE=/private/tmp/vk-turn-go-build-cache \
GOPATH=/private/tmp/vk-turn-go \
make xcframework
```

## Configure signing locally

Open `VKTurnProxy/VKTurnProxy.xcodeproj` in Xcode.

For both targets:

- `VKTurnProxy`
- `PacketTunnel`

Set local signing to your Apple Developer team and private bundle IDs. Do not commit personal signing, provisioning, certificate, `.p12`, or device UDID material.

Both targets must share the same App Group entitlement. The PacketTunnel extension must have Network Extension / packet tunnel capability.

## Build and install

Use Xcode with a physical iPhone selected as the destination.

Build order:

1. Build `WireGuardTURN.xcframework`.
2. Open the project in Xcode.
3. Confirm signing for both targets.
4. Build and run on the iPhone.
5. Accept the VPN profile prompt on device.

Simulator is not sufficient for PacketTunnel validation.

## Minimal validation checklist

- App launches.
- Settings screen opens.
- VPN profile can be created.
- Connect starts PacketTunnel extension.
- Logs view shows redacted logs.
- No full `proxy_config`, private key, PSK, VK link, WRAP key, TURN username/password, or browser profile appears in exported logs.
- Disconnect returns to a stable disconnected state.

Do not claim WiFi/LTE handoff validation until tested on a physical iPhone with actual interface changes.

## Current blocker from this machine

On 2026-05-15 this environment has Go and XcodeGen, but not full Xcode:

```text
xcode-select -p
/Library/Developer/CommandLineTools
```

`make -C WireGuardBridge xcframework` fails because `xcrun` cannot locate the `iphoneos` SDK. Install/select full Xcode before local iPhone build validation.
