# Keychain migration

## Summary

WireGuard private key, preshared key, VK link, and WRAP key are stored in the iOS Keychain instead of `@AppStorage` / `UserDefaults`.

## Stored in Keychain

- `privateKey`
- `presharedKey`
- `vkLink`
- `wrapKeyHex`

Items use generic-password Keychain records under service `com.vkturnproxy.app.secrets` with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.

## Migration

On app launch, settings open, and connect attempt, the app checks legacy `UserDefaults` values. Non-empty legacy values are copied to Keychain and removed from `UserDefaults` only after the Keychain write succeeds.

## Import Behavior

- Settings-only backups do not touch Keychain secrets.
- Legacy full backups and connection links write secret fields into Keychain.
- Legacy `UserDefaults` secret keys are cleared after import.

## Reset

Settings includes `Reset Keychain Secrets`, which deletes private key, preshared key, VK link, and WRAP key. Non-secret preferences, TURN cache, and captured browser profile remain unchanged.

## Remaining Work

- Validate migration on a physical iPhone after installing over a build that still used `@AppStorage`.
- `TunnelManager` still passes generated `wg_config` and `proxy_config` through `NETunnelProviderProtocol.providerConfiguration` so the PacketTunnel extension can start. That may persist secret-bearing runtime config in iOS Network Extension preferences while the VPN profile exists. Do not treat Keychain migration as complete secret isolation until this handoff model is redesigned and device-tested.
- Add import payload size caps and schema validation.
- Decide whether `peerAddress` should also move out of `UserDefaults` for private-hostname hygiene.
