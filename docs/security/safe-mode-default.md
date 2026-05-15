# Safe mode default

## Summary

Fresh installs default to safe routing instead of silently becoming a full-device VPN.

## Defaults

- `fullTunnelMode = false`
- `includeAllNetworks = false`
- `allowedIPs = 192.168.102.0/24`
- `numConnections = 4`
- `mtu = 1280`

Safe mode keeps the tunnel startup flow intact, but the PacketTunnel extension installs only non-default IPv4 routes derived from `allowedIPs`. `0.0.0.0/0` is ignored while safe mode is active.

## Full-device VPN

`Full-device VPN` is an explicit Settings toggle. Enabling it shows a warning before storing the preference.

When enabled:

- `includeAllNetworks = true`
- PacketTunnel installs the default IPv4 route
- iOS may re-prompt for VPN permission after the profile changes

## Backup/import behavior

Safe backup and connection-link import do not enable full-device VPN. Users must explicitly enable it on the device.

## Validation limits

This patch has compile-only and CI validation. Actual routing behavior still requires a physical iPhone with signed Network Extension entitlements.
