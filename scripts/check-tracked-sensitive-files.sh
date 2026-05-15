#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

failed=0

private_paths=$(
    git ls-files \
        | grep -E '(^|/)([^/]+\.p12|[^/]+\.mobileprovision|[^/]+\.provisionprofile|\.env(\..*)?)$|(^|/)DerivedData(/|$)|\.xcarchive(/|$)' \
        || true
)

if [ -n "$private_paths" ]; then
    echo "Tracked private/signing files are forbidden:" >&2
    echo "$private_paths" >&2
    failed=1
fi

export_options=$(git ls-files '*ExportOptions*.plist' || true)
if [ -n "$export_options" ]; then
    echo "Warning: tracked ExportOptions*.plist files exist; keep personal variants ignored:" >&2
    echo "$export_options" >&2
fi

scan_pattern='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|vkturnproxy://import\?data=[A-Za-z0-9_+/%=-]{32,}|"((privateKey)|(presharedKey)|(vkLink)|(wrapKeyHex))"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_+/=-]{24,}"|"((turn_password)|(password))"[[:space:]]*:[[:space:]]*"[^"<>{}[:space:]]{8,}"|"((browser_fp)|(device))"[[:space:]]*:[[:space:]]*"[^"]{64,}"'

if git grep -nE -- "$scan_pattern" -- . >/tmp/vk-turn-sensitive-grep.txt 2>/dev/null; then
    echo "Potential plaintext secret material found in tracked files:" >&2
    cat /tmp/vk-turn-sensitive-grep.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-sensitive-grep.txt

if git grep -nE -- '@AppStorage\("(privateKey|presharedKey|vkLink|wrapKeyHex)"' -- 'VKTurnProxy/**/*.swift' >/tmp/vk-turn-secret-appstorage.txt 2>/dev/null; then
    echo "Secret-bearing fields must not use @AppStorage/UserDefaults-backed storage:" >&2
    cat /tmp/vk-turn-secret-appstorage.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-secret-appstorage.txt

if git grep -nF -- 'proto.includeAllNetworks = true' -- 'VKTurnProxy/**/*.swift' >/tmp/vk-turn-include-all-networks.txt 2>/dev/null; then
    echo "includeAllNetworks must not be a silent constant true default:" >&2
    cat /tmp/vk-turn-include-all-networks.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-include-all-networks.txt

if git grep -nE -- '(@AppStorage\("allowedIPs"\).*"0\.0\.0\.0/0"|var allowedIPs: String = "0\.0\.0\.0/0")' -- 'VKTurnProxy/**/*.swift' >/tmp/vk-turn-default-routes.txt 2>/dev/null; then
    echo "Fresh allowedIPs default must not be the full-device default route:" >&2
    cat /tmp/vk-turn-default-routes.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-default-routes.txt

if git grep -nE -- '(@AppStorage\("numConnections"\).*=[[:space:]]*30|var numConnections: Int = 30)' -- 'VKTurnProxy/**/*.swift' >/tmp/vk-turn-default-conns.txt 2>/dev/null; then
    echo "Fresh numConnections default must stay conservative:" >&2
    cat /tmp/vk-turn-default-conns.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-default-conns.txt

safe_export_body=$(
    awk '/static func currentSafeConfig\(\)/,/^    }/' VKTurnProxy/VKTurnProxy/BackupManager.swift
)
if printf '%s\n' "$safe_export_body" \
    | grep -nE 'string\(forKey: "(privateKey|peerPublicKey|presharedKey|vkLink|peerAddress|wrapKeyHex)"|VKProfileCache|credsPoolURL|CredCache|turnPool|vkProfile' >/tmp/vk-turn-safe-export-grep.txt; then
    echo "Safe backup export appears to read secret-bearing state:" >&2
    cat /tmp/vk-turn-safe-export-grep.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-safe-export-grep.txt

safe_settings_body=$(
    awk '/struct SafeBackupSettings: Codable/,/^}/' VKTurnProxy/VKTurnProxy/AppConfig.swift
)
if printf '%s\n' "$safe_settings_body" \
    | grep -nE 'privateKey|peerPublicKey|presharedKey|vkLink|peerAddress|wrapKeyHex|turnPool|vkProfile|browser_fp|device' >/tmp/vk-turn-safe-settings-grep.txt; then
    echo "SafeBackupSettings contains secret-bearing fields:" >&2
    cat /tmp/vk-turn-safe-settings-grep.txt >&2
    failed=1
fi
rm -f /tmp/vk-turn-safe-settings-grep.txt

exit "$failed"
