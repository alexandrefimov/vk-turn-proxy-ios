# Private local iPhone build

## Goal

Build and install a private development build on a physical iPhone without
public TestFlight, App Store, or GitHub Release distribution.

This is the first real-device workflow. It is for validating signing,
PacketTunnel startup, safe-mode defaults, import, and redacted diagnostics.

## Current status

As of 2026-05-15:

- Go, XcodeGen, full Xcode, and the iPhoneOS SDK are installed locally.
- `WireGuardBridge/build/WireGuardTURN.xcframework` builds locally.
- Compile-only `xcodebuild` with `CODE_SIGNING_ALLOWED=NO` passes locally.
- Xcode unit tests pass locally and in GitHub Actions.
- Physical iPhone validation has not been run.
- A paid Apple Developer Program account is still required for device signing
  and Network Extension entitlement provisioning.

## Repository signing map

The checked-in Xcode project is generated from `VKTurnProxy/project.yml`.
Do not edit signing settings in Xcode and then regenerate without carrying the
intentional changes back into `project.yml`.

Current checked-in values:

| Target | Bundle ID | Entitlements |
| --- | --- | --- |
| `VKTurnProxy` | `com.vkturnproxy.app` | `VKTurnProxy/VKTurnProxy.entitlements` |
| `PacketTunnel` | `com.vkturnproxy.app.tunnel` | `PacketTunnel/PacketTunnel.entitlements` |
| `VKTurnProxyTests` | `com.vkturnproxy.app.tests` | none |

Current shared App Group:

```text
group.com.vkturnproxy.app
```

Current Network Extension entitlement value in both app and extension:

```text
packet-tunnel-provider
```

The app and extension also currently request Wi-Fi information entitlement.

## What requires the paid account

You can continue CI, Go builds, compile-only Xcode builds, unit tests, and
documentation without the paid account.

The paid Apple Developer Program account becomes blocking when you need to:

- sign both app targets for a physical iPhone;
- register explicit App IDs;
- enable the Network Extension capability;
- provision `packet-tunnel-provider`;
- register and attach the shared App Group;
- create or let Xcode create development provisioning profiles;
- start the PacketTunnel extension on device.

Apple's docs describe Network Extension as an entitlement-backed capability,
and packet tunnel providers require the Network Extension entitlement. Xcode
capability availability depends on platform and program membership.

## Apple Developer portal setup

Use private, unique identifiers for your fork. Do not use real server names,
device UDIDs, certificates, `.p12` files, or provisioning profiles in git.

Recommended shape:

```text
App bundle ID:       <your.reverse.dns>.vkturnproxy
Extension bundle ID: <your.reverse.dns>.vkturnproxy.tunnel
App Group:           group.<your.reverse.dns>.vkturnproxy
```

In Certificates, Identifiers & Profiles:

1. Create an explicit App ID for the main app.
2. Create an explicit App ID for the PacketTunnel extension.
3. Enable Network Extensions for both IDs, matching the current repo
   entitlement value `packet-tunnel-provider`.
4. Enable App Groups for both IDs.
5. Register one shared App Group and attach it to both IDs.
6. Enable Wi-Fi information only if your account allows it and the local build
   still requires the current entitlement.
7. Let Xcode manage development provisioning profiles, or create development
   profiles manually and install them locally.

If signing fails with an entitlement mismatch, inspect the provisioning profile:
the profile entitlements must contain the same Network Extension and App Group
values that the target entitlements request.

## Local identifier strategy

There are two safe ways to handle private signing identifiers:

- **Temporary local build:** change bundle IDs, team, and App Group in Xcode for
  your local working tree, build, test, and do not commit those local signing
  changes.
- **Private fork baseline:** make a small dedicated commit that changes only
  the checked-in bundle IDs, App Group, and development team placeholders for
  this fork. Do not include provisioning profiles, certificates, `.p12` files,
  App Store Connect data, or device UDIDs.

Do not mix signing changes with tunnel behavior, logging, storage, import, or UI
changes. Signing is its own patch.

## Select full Xcode

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -runFirstLaunch
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
```

`xcrun --sdk iphoneos --show-sdk-path` must print an SDK path. If it fails, the
Go XCFramework and iOS build cannot be validated.

## Install CLI dependencies

```bash
brew install go xcodegen
```

## Validate before signing

From the repository root:

```bash
sh scripts/validate-local.sh
```

This runs:

- whitespace checks;
- tracked-secret/signing-file guard;
- plist and entitlement lint;
- Go tests;
- WireGuardBridge package tests;
- compile-only iPhoneOS build when the XCFramework exists;
- iOS simulator XCTest.

## Regenerate the Xcode project

Regenerate only when `VKTurnProxy/project.yml` changed:

```bash
xcodegen --spec VKTurnProxy/project.yml --project VKTurnProxy --use-cache
```

The checked-in `.xcodeproj` should then be reviewed like any other generated
change.

## Build the Go XCFramework

From the repository root:

```bash
GOCACHE=/private/tmp/vk-turn-go-build-cache \
GOPATH=/private/tmp/vk-turn-go \
make -C WireGuardBridge xcframework
```

Expected output:

```text
WireGuardBridge/build/WireGuardTURN.xcframework
```

## Configure signing in Xcode

Open:

```bash
open VKTurnProxy/VKTurnProxy.xcodeproj
```

For both targets:

- `VKTurnProxy`
- `PacketTunnel`

Check:

- Team is your Apple Developer Program team.
- Bundle IDs match the explicit App IDs from the developer portal.
- App Group matches both target entitlements and provisioning profiles.
- Network Extension capability includes packet tunnel provider.
- Signing is automatic unless you intentionally use local manual profiles.
- No local provisioning profile or certificate file is added to the repository.

The tests target may use a derived test bundle ID. It does not need PacketTunnel
or App Group entitlements.

## Build and install

Use Xcode with a physical iPhone selected as destination.

Build order:

1. Build `WireGuardTURN.xcframework`.
2. Open the project in Xcode.
3. Confirm signing for app and PacketTunnel targets.
4. Build and run the `VKTurnProxy` scheme on the iPhone.
5. Accept the iOS VPN profile prompt on the device.

Simulator is not sufficient for PacketTunnel validation.

## Minimal device validation checklist

Record the date, iOS version, device model family, commit hash, and whether the
build used temporary local signing edits or committed fork identifiers. Do not
record device UDID.

Check:

- App launches.
- Settings screen opens.
- VPN profile can be created.
- Fresh install defaults to safe/split mode, not silent full-device VPN.
- Connection import works with a test or personal payload.
- Import payload is treated as secret and not pasted into logs or screenshots.
- Connect starts the PacketTunnel extension.
- Disconnect returns to a stable disconnected state.
- Logs view shows redacted logs.
- Exported logs do not include full `proxy_config`, private key, PSK, VK link,
  WRAP key, TURN username/password, import payload, browser profile, `device`,
  or `browser_fp`.
- Settings-only backup export contains no plaintext secrets.

Do not claim Wi-Fi/LTE handoff validation until tested on a physical iPhone with
actual interface changes.

## Troubleshooting

### Missing Network Extension entitlement

Symptom: build/signing fails or PacketTunnel cannot start.

Check that both the target entitlements and provisioning profiles contain:

```text
com.apple.developer.networking.networkextension = packet-tunnel-provider
```

### App Group mismatch

Symptom: logs, shared cache, import state, or extension communication fails.

Check that both targets and both provisioning profiles contain the same
`com.apple.security.application-groups` value.

### XCFramework missing

Symptom: Xcode cannot link `WireGuardTURN.xcframework`.

Run:

```bash
GOCACHE=/private/tmp/vk-turn-go-build-cache \
GOPATH=/private/tmp/vk-turn-go \
make -C WireGuardBridge xcframework
```

### XcodeGen overwrote local signing edits

Symptom: bundle IDs or App Group reverted after regeneration.

Expected behavior: `VKTurnProxy/project.yml` is canonical. Either repeat the
local uncommitted signing edits in Xcode, or make a dedicated signing-only
commit in the private fork.

## Do not run yet

Do not run `release.sh` during hardening. It is a public release/TestFlight
pipeline and remains blocked until security and license review are complete.

Do not create public distribution instructions until:

- license compatibility is resolved;
- runtime hardening is complete;
- logs and backups are verified on device;
- a release threat model is written.

## Codex escalation commands

When running under Codex, use escalation for:

```bash
sh scripts/validate-local.sh
```

```bash
sh scripts/run-xcode-tests.sh
```

```bash
xcodegen --spec VKTurnProxy/project.yml --project VKTurnProxy --use-cache
```

```bash
xcodebuild -project VKTurnProxy/VKTurnProxy.xcodeproj -scheme VKTurnProxy -configuration Debug -sdk iphoneos -derivedDataPath /private/tmp/vk-turn-derived-data CODE_SIGNING_ALLOWED=NO -quiet build
```

```bash
git push origin main
gh run watch <run-id> --repo alexandrefimov/vk-turn-proxy-ios --exit-status
```

## References

- Apple Developer Documentation: Capabilities
  `https://developer.apple.com/documentation/Xcode/capabilities`
- Apple Developer Documentation: Network Extensions Entitlement
  `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension`
- Apple Developer Documentation: Packet tunnel provider
  `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- Apple Developer Documentation: Configuring app groups
  `https://developer.apple.com/documentation/xcode/configuring-app-groups`
