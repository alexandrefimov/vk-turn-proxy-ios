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
| Full Xcode | installed and selected, `/Applications/Xcode.app/Contents/Developer` |
| iPhoneOS SDK | installed, iPhoneOS 26.4 |
| Go tests | pass with temp cache paths |
| Go XCFramework build | passes with temp cache paths |
| Xcode app build | compile-only build passes with `CODE_SIGNING_ALLOWED=NO` |
| Physical device validation | not run |

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
go test .
```

Use `go test .` from `WireGuardBridge`. After `make xcframework`, the
ignored `WireGuardBridge/build/goroot` staging tree sits under the Go module
directory, so `go test ./...` also walks copied Go runtime test fixtures and is
not a valid project validation command unless `WireGuardBridge/build/` is
removed first.

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
xcodegen --spec VKTurnProxy/project.yml --project VKTurnProxy --use-cache
```

Do not commit generated project churn unless the task is explicitly about project settings.

## Codex escalation checklist

Run these commands with Codex escalation. They need Xcode services outside the sandbox, GitHub/network access, or project-generation cache writes:

```bash
sh scripts/validate-local.sh
```

```bash
sh scripts/run-xcode-tests.sh
```

```bash
xcodebuild -project VKTurnProxy/VKTurnProxy.xcodeproj -scheme VKTurnProxy -configuration Debug -sdk iphoneos -derivedDataPath /private/tmp/vk-turn-derived-data CODE_SIGNING_ALLOWED=NO -quiet build
```

```bash
xcodegen --spec VKTurnProxy/project.yml --project VKTurnProxy --use-cache
```

```bash
git fetch upstream
git push origin main
```

```bash
gh run list --repo alexandrefimov/vk-turn-proxy-ios --branch main --limit 5
gh run watch <run-id> --repo alexandrefimov/vk-turn-proxy-ios --exit-status
```

These checks normally run without escalation:

```bash
git diff --check
sh scripts/check-tracked-sensitive-files.sh
plutil -lint VKTurnProxy/VKTurnProxy/Info.plist VKTurnProxy/PacketTunnel/Info.plist VKTurnProxy/VKTurnProxy/VKTurnProxy.entitlements VKTurnProxy/PacketTunnel/PacketTunnel.entitlements
GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go go test ./...
(cd WireGuardBridge && GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go go test .)
```

## Blocked operations in this environment

- Apple Developer account setup.
- Network Extension entitlement approval.
- Physical iPhone run.
- Device validation.

Document these as blockers instead of claiming validation passed.
