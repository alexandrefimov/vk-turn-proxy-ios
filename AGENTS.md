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
- Default integration branch: `main`.
- Work directly on `main` when there is a single active agent and the change is small, reviewed locally, and validated before push.
- Use short-lived topic branches only when the work needs isolation, is risky, or multiple agents may run in parallel.
- Merge completed topic branches back into `main` promptly and delete them after push.
- Keep commits small and reviewable.

## Tooling notes
- Prefer `rg` / `rg --files` for repository inspection.
- Use `GOCACHE` and `GOPATH` under `/private/tmp` when sandboxed Go commands cannot write to `~/Library/Caches` or `~/go`.
- Go CLI checks are useful, but iOS XCFramework builds require full Xcode with the iPhoneOS SDK selected by `xcode-select`.
- Do not regenerate or commit Xcode project churn unless the task explicitly requires project generation changes.
- Do not run `release.sh` during hardening. It is a public TestFlight/GitHub Release pipeline and is blocked until security and license review are done.

## Codex escalation notes
Run these through tool escalation in Codex instead of retrying after sandbox failures:
- `sh scripts/validate-local.sh`
- `sh scripts/run-xcode-tests.sh`
- direct `xcodebuild ...` compile-only builds
- `xcodegen --spec VKTurnProxy/project.yml --project VKTurnProxy --use-cache` when project regeneration is intentional
- network commands such as `git fetch upstream`, `git push origin main`, and `gh run ...`

These usually do not need escalation:
- `rg`, `sed`, `plutil`, `git diff`, `git status`, `git log`
- `sh scripts/check-tracked-sensitive-files.sh`
- Go checks with `GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go`

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
