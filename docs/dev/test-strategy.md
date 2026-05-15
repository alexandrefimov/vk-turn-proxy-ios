# Test strategy

## Current automated checks

CI runs:

- tracked secret/signing-file guard;
- safe-backup guard;
- `includeAllNetworks` silent-default guard;
- whitespace check;
- plist/entitlements lint;
- Go package tests;
- WireGuardBridge XCFramework build;
- Xcode compile-only build with signing disabled.

## Useful next tests

- Swift unit tests for import validation and redaction helpers.
- Swift unit tests for safe-mode routing decisions after route logic is moved behind a small pure helper.
- Golden JSON fixtures for settings-only backup and connection-link import.

## Not automatable here

PacketTunnel routing, Network Extension profile prompts, full-device routing, captcha fallback, and WiFi/LTE handoff require a signed build on a physical iPhone.
