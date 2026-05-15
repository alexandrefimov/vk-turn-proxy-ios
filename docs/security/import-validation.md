# Import validation

## Summary

Backup and connection-link imports now reject oversized payloads and validate decoded schema before anything is written to Keychain, UserDefaults, or App Group files.

## Size caps

- Backup JSON file: 512 KiB.
- `vkturnproxy://` or clipboard connection-link input: 64 KiB.
- Connection-link base64 payload: 48 KiB.
- Decoded connection-link JSON: 32 KiB.

These limits are intentionally above normal generated payload size but low enough to reject accidental or hostile oversized imports early.

## Schema checks

Imports reject unsupported top-level or nested JSON fields for:

- settings-only backups;
- legacy full backups;
- connection links;
- legacy `turn_pool`;
- legacy `vk_profile`.

Unsupported schema versions are rejected before apply.

## Value checks

Validation covers:

- WireGuard private/public/preshared key shape;
- tunnel address CIDR;
- allowed IP CIDRs;
- DNS server IP list;
- `host:port` server fields;
- VK link URL shape;
- WRAP key length/hex encoding;
- `numConnections` and cooldown bounds;
- TURN cache entry count and basic entry shape;
- captured VK profile field lengths.

## Non-goals

- This does not change tunnel routing, full-tunnel behavior, MTU, or storage semantics.
- This does not make `vkturnproxy://` links safe to share. They still contain secret material and must be treated as secrets.
- This does not remove secret-bearing `wg_config` / `proxy_config` from Network Extension provider configuration.
