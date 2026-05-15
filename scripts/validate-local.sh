#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

git diff --check
sh scripts/check-tracked-sensitive-files.sh

if command -v plutil >/dev/null 2>&1; then
    plutil -lint \
        VKTurnProxy/VKTurnProxy/Info.plist \
        VKTurnProxy/PacketTunnel/Info.plist \
        VKTurnProxy/VKTurnProxy/VKTurnProxy.entitlements \
        VKTurnProxy/PacketTunnel/PacketTunnel.entitlements
else
    echo "Skipping plist lint: plutil not found"
fi

if command -v go >/dev/null 2>&1; then
    GOCACHE=${GOCACHE:-/private/tmp/vk-turn-go-build-cache}
    GOPATH=${GOPATH:-/private/tmp/vk-turn-go}
    export GOCACHE GOPATH
    go test ./...
    (cd WireGuardBridge && go test .)
else
    echo "Skipping Go tests: go not found"
fi

if command -v xcodebuild >/dev/null 2>&1; then
    if [ -d WireGuardBridge/build/WireGuardTURN.xcframework ]; then
        xcodebuild \
            -project VKTurnProxy/VKTurnProxy.xcodeproj \
            -scheme VKTurnProxy \
            -configuration Debug \
            -sdk iphoneos \
            -derivedDataPath /private/tmp/vk-turn-derived-data \
            CODE_SIGNING_ALLOWED=NO \
            -quiet \
            build
        sh scripts/run-xcode-tests.sh
    else
        echo "Skipping Xcode compile-only build: WireGuardTURN.xcframework is absent"
        echo "Run: GOCACHE=/private/tmp/vk-turn-go-build-cache GOPATH=/private/tmp/vk-turn-go make -C WireGuardBridge xcframework"
    fi
else
    echo "Skipping Xcode compile-only build: xcodebuild not found"
fi
