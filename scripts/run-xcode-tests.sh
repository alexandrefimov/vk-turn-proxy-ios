#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "Skipping Xcode unit tests: xcodebuild not found"
    exit 0
fi

if ! command -v xcrun >/dev/null 2>&1; then
    echo "Skipping Xcode unit tests: xcrun not found"
    exit 0
fi

if [ ! -d WireGuardBridge/build/WireGuardTURN.xcframework ]; then
    echo "Skipping Xcode unit tests: WireGuardTURN.xcframework is absent"
    echo "Run: GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go make -C WireGuardBridge xcframework"
    exit 0
fi

destination=${XCODE_TEST_DESTINATION:-}
simulator_id=
if [ -z "$destination" ]; then
    simulator_id=$(
        xcrun simctl list devices available 2>/dev/null \
            | sed -n 's/^[[:space:]]*iPhone[^()]* (\([0-9A-F-]*\)) (.*/\1/p' \
            | head -n 1
    )
    if [ -z "$simulator_id" ]; then
        if [ -n "${CI:-}" ]; then
            echo "No available iPhone simulator found for Xcode unit tests" >&2
            exit 1
        fi
        echo "Skipping Xcode unit tests: no available iPhone simulator found"
        exit 0
    fi
    destination="platform=iOS Simulator,id=$simulator_id"
fi

if [ -n "$simulator_id" ]; then
    xcrun simctl boot "$simulator_id" >/dev/null 2>&1 || true
    xcrun simctl bootstatus "$simulator_id" -b >/dev/null
    xcrun simctl terminate "$simulator_id" com.vkturnproxy.app >/dev/null 2>&1 || true
    xcrun simctl uninstall "$simulator_id" com.vkturnproxy.app >/dev/null 2>&1 || true
fi

xcodebuild \
    -project VKTurnProxy/VKTurnProxy.xcodeproj \
    -scheme VKTurnProxy \
    -configuration Debug \
    -sdk iphonesimulator \
    -destination "$destination" \
    -derivedDataPath "${DERIVED_DATA_PATH:-/private/tmp/vk-turn-test-derived-data}" \
    CODE_SIGNING_ALLOWED=NO \
    -quiet \
    test
