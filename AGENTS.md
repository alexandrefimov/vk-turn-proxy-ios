# AGENTS.md

## Scope
This repository is an iOS Network Extension client for vk-turn-proxy.

## Product goal
Private, auditable iOS client for personal testing first. Security hardening before features.

## Non-goals for now
- Public App Store release.
- Public TestFlight rollout.
- Large UI redesign.
- Protocol redesign.
- Custom vk-turn-proxy server fork unless strictly required.

## Security rules
- Never commit secrets:
  - WireGuard private keys
  - preshared keys
  - VK call links
  - TURN credentials
  - WRAP keys
  - captured browser profiles
  - Apple certificates
  - provisioning profiles
  - .p12 files
  - App Store Connect credentials
  - real server IPs unless intentionally documented as examples
- Redact logs before export.
- No plaintext backup of secrets.
- Prefer Keychain for secrets.
- UserDefaults/AppStorage may store only non-sensitive UI preferences.
- Full-tunnel mode must not be the silent default.
- Any import link containing private key material is secret.

## Git workflow
- origin should be our fork.
- upstream should be https://github.com/anton48/vk-turn-proxy-ios.git
- Use topic branches:
  - audit/baseline
  - hardening/secrets-keychain
  - hardening/redacted-logs
  - hardening/safe-mode
  - integration/import-link
- Keep commits small and reviewable.

## Validation
Because Network Extension requires Apple signing and a physical iOS device:
- run static checks where possible
- build Go XCFramework if environment supports it
- run Swift/Xcode build only when full Xcode and signing are available
- never claim device validation without actual device run

## Output expectations
Each task must end with:
- summary
- files changed
- commands run
- validation result
- security risks
- follow-up
