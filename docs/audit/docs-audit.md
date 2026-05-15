# Documentation audit

## Scope

Reviewed:

- `README.md`
- `AGENTS.md`
- `SECURITY.md`
- `docs/audit/ios-security-baseline.md`
- `docs/audit/redaction-notes.md`
- `VKTurnProxy/project.yml`
- `WireGuardBridge/Makefile`
- `release.sh`
- `quick_link.py`

## Updates made

- Removed public TestFlight install guidance from `README.md`.
- Reframed README for private hardening and local-device builds.
- Added toolchain documentation in `docs/dev/toolchain.md`.
- Added private local iPhone build documentation in `docs/build/ios-local-build.md`.
- Updated `SECURITY.md` with current hardening status.
- Updated baseline audit to reflect installed Go/XcodeGen and completed redacted-log patch.
- Added agent instructions for sandboxed Go cache paths and avoiding release pipeline usage during hardening.
- Added no-plaintext-backup notes and local/CI validation scripts.

## Current documentation gaps

- No Keychain migration design yet.
- No safe-mode/full-tunnel UX design yet.
- No import-link schema document yet.
- No license resolution document yet.

## Next docs to add with future branches

- `docs/security/keychain-migration.md`
- `docs/security/safe-mode-default.md`
- `docs/integration/import-link-schema.md`
- `docs/legal/license-risk.md`
