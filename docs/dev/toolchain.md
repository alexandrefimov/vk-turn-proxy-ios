# Toolchain and environment

## Required tools

- Homebrew
- Go 1.21 or newer
- XcodeGen
- Full Xcode 15 or newer
- Apple Developer Program account
- Network Extension capability for PacketTunnel
- App Group capability shared by the app and extension
- Physical iPhone for validation

## Current machine status

Checked on 2026-05-15:

| Tool | Status |
| --- | --- |
| Homebrew | installed |
| Go | installed via Homebrew, `go1.26.3 darwin/arm64` |
| XcodeGen | installed via Homebrew, `2.45.4` |
| Swift CLI | installed with Command Line Tools |
| Full Xcode | missing / not selected |
| iPhoneOS SDK | missing |
| Go tests | pass with temp cache paths |
| Go XCFramework build | blocked by missing iPhoneOS SDK |
| Xcode app build | blocked by missing full Xcode |

## Install CLI tools

```bash
brew install go xcodegen
```

## Verify CLI tools

```bash
go version
xcodegen --version
xcode-select -p
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
```

`xcode-select -p` must point to full Xcode, usually:

```text
/Applications/Xcode.app/Contents/Developer
```

If it points to `/Library/Developer/CommandLineTools`, iOS builds cannot run.

## Sandboxed Go commands

When Go cannot write to `~/Library/Caches/go-build` or `~/go`, use writable temp paths:

```bash
GOCACHE=/private/tmp/vk-turn-go-build-cache \
GOPATH=/private/tmp/vk-turn-go \
go test ./...
```

For XCFramework builds in a sandboxed shell:

```bash
GOCACHE=/private/tmp/vk-turn-go-build-cache \
GOPATH=/private/tmp/vk-turn-go \
make -C WireGuardBridge xcframework
```

This still requires full Xcode and the iPhoneOS SDK.

## XcodeGen

The checked-in Xcode project is generated from `VKTurnProxy/project.yml`.

Regenerate only when project metadata intentionally changes:

```bash
cd VKTurnProxy
xcodegen generate
```

Do not commit generated project churn unless the task is explicitly about project settings.

## Blocked operations in this environment

- Full Xcode installation.
- Apple Developer account setup.
- Network Extension entitlement approval.
- Physical iPhone run.
- Device validation.

Document these as blockers instead of claiming validation passed.
