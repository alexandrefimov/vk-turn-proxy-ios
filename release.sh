#!/usr/bin/env bash
# release.sh — full release pipeline for an already-tagged build.
#
# What it does, in order:
#   1. Sanity-check the environment (clean tree, tag exists, project.yml
#      build number matches the tag, App Store Connect API key file is
#      present, gh CLI is authenticated).
#   2. Build the Go xcframework (WireGuardBridge/Makefile).
#   3. xcodebuild archive (Release configuration) into
#      build_output/VKTurnProxy.xcarchive — overwriting any prior archive.
#   4. xcodebuild -exportArchive with destination=upload to push the
#      build to TestFlight via the App Store Connect API key.
#   5. xcodebuild -exportArchive with destination=export to produce a
#      local VKTurnProxy.ipa under build_output/Export-build<N>/.
#   6. Attach the IPA to the GitHub Release for <tag>. Creates the
#      release first (using the tag's own annotation as title + body)
#      if no release exists yet for that tag; otherwise uploads the IPA
#      with --clobber to replace any prior asset of the same name.
#
# Why two -exportArchive runs (steps 4 and 5)?
#   xcodebuild's destination=upload uploads the IPA directly to App
#   Store Connect without leaving it on disk. To attach the same IPA to
#   a GitHub Release we have to re-export with destination=export. The
#   archive is the same in both runs, so signing and content match
#   exactly — only the disposition differs.
#
# Usage:
#     ./release.sh <tag>
#
# Example:
#     git tag -a v1.0-build35 -m "..."
#     git push origin v1.0-build35
#     ./release.sh v1.0-build35
#
# Prerequisites checked at startup:
#   - Git tag <tag> exists locally
#   - VKTurnProxy/project.yml's CURRENT_PROJECT_VERSION matches <N>
#     extracted from the tag (everything after the last "build")
#   - VKTurnProxy/AppStoreConnect.env defines APPSTORE_KEY_ID,
#     APPSTORE_ISSUER_ID, APPSTORE_KEY_PATH (sourced into env)
#   - Working tree is clean (no uncommitted changes)
#   - gh CLI is installed and authenticated for the upstream repo

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
    cat >&2 <<EOF
Usage: $0 <tag>

Example: $0 v1.0-build35

The tag must already exist locally (and ideally also pushed to origin).
The build number is extracted from the tag suffix after "build".
EOF
    exit 64
fi

# Extract build number — everything after the last "build" in the tag.
# v1.0-build35 → 35
BUILD_NUM="${TAG##*build}"
if [[ ! "$BUILD_NUM" =~ ^[0-9]+$ ]]; then
    echo "ERROR: tag must end with build<N>, got: $TAG" >&2
    exit 64
fi

# Run from repo root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Helpful colour codes for stage banners — falls back to no-colour if
# stdout isn't a terminal.
if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; CYAN=$'\033[36m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=""; CYAN=""; GREEN=""; RED=""; RESET=""
fi
banner() { printf '\n%s==> %s%s\n' "$BOLD$CYAN" "$*" "$RESET"; }
ok()     { printf '%s%s%s\n' "$GREEN"          "$*" "$RESET"; }
fail()   { printf '%s%s%s\n' "$RED"            "$*" "$RESET" >&2; }

# ─── Step 1: sanity checks ─────────────────────────────────────────────────
banner "Verifying environment for $TAG (build $BUILD_NUM)"

if [[ -n "$(git status --porcelain)" ]]; then
    fail "Working tree is dirty. Commit or stash before releasing."
    git status --short
    exit 1
fi

if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    fail "Tag $TAG does not exist locally."
    fail "Create it first:  git tag -a $TAG -m '...'  &&  git push origin $TAG"
    exit 1
fi

PROJECT_YML="VKTurnProxy/project.yml"
PROJ_BUILD=$(awk '/^[[:space:]]+CURRENT_PROJECT_VERSION:/ {print $NF; exit}' "$PROJECT_YML")
if [[ "$PROJ_BUILD" != "$BUILD_NUM" ]]; then
    fail "project.yml CURRENT_PROJECT_VERSION = $PROJ_BUILD, but tag build = $BUILD_NUM"
    fail "Bump project.yml + commit + retag, then re-run."
    exit 1
fi

ENV_FILE="VKTurnProxy/AppStoreConnect.env"
if [[ ! -f "$ENV_FILE" ]]; then
    fail "$ENV_FILE not found — App Store Connect API credentials missing."
    exit 1
fi

# Source key paths so we can sanity-check them without leaking values.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
for var in APPSTORE_KEY_ID APPSTORE_ISSUER_ID APPSTORE_KEY_PATH; do
    if [[ -z "${!var:-}" ]]; then
        fail "$ENV_FILE missing required variable: $var"
        exit 1
    fi
done
if [[ ! -f "$APPSTORE_KEY_PATH" ]]; then
    fail "APPSTORE_KEY_PATH=$APPSTORE_KEY_PATH does not exist on disk."
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    fail "gh CLI not installed — needed for GitHub Release upload."
    exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
    fail "gh CLI not authenticated. Run: gh auth login"
    exit 1
fi

ok "All checks passed."

# ─── Step 2: Go xcframework ────────────────────────────────────────────────
banner "Building Go xcframework"
( cd WireGuardBridge && make xcframework )
ok "xcframework built."

# ─── Step 3: archive Release config ────────────────────────────────────────
banner "Archiving Release configuration"
ARCHIVE_PATH="VKTurnProxy/build_output/VKTurnProxy.xcarchive"
rm -rf "$ARCHIVE_PATH"
xcodebuild \
    -project VKTurnProxy/VKTurnProxy.xcodeproj \
    -scheme VKTurnProxy \
    -destination 'generic/platform=iOS' \
    -configuration Release \
    -archivePath "$ARCHIVE_PATH" \
    archive \
    -allowProvisioningUpdates \
    2>&1 | tail -3
ok "Archive created at $ARCHIVE_PATH"

# ─── Step 4: TestFlight upload ─────────────────────────────────────────────
banner "Uploading to TestFlight (App Store Connect)"
EXPORT_TF_DIR="VKTurnProxy/build_output/Export-tf$BUILD_NUM"
rm -rf "$EXPORT_TF_DIR"
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_TF_DIR" \
    -exportOptionsPlist VKTurnProxy/ExportOptions.plist \
    -authenticationKeyPath "$APPSTORE_KEY_PATH" \
    -authenticationKeyID "$APPSTORE_KEY_ID" \
    -authenticationKeyIssuerID "$APPSTORE_ISSUER_ID" \
    -allowProvisioningUpdates \
    2>&1 | tail -8
ok "TestFlight upload submitted."

# ─── Step 5: local IPA export ──────────────────────────────────────────────
banner "Exporting local IPA for GitHub Release"
EXPORT_LOCAL_DIR="VKTurnProxy/build_output/Export-build$BUILD_NUM"
EXPORT_LOCAL_PLIST=$(mktemp -t ExportOptions-export.XXXXXX.plist)
trap "rm -f '$EXPORT_LOCAL_PLIST'" EXIT

# Same options as VKTurnProxy/ExportOptions.plist but destination=export
# instead of destination=upload, so xcodebuild leaves the IPA on disk
# rather than streaming it to App Store Connect.
cat > "$EXPORT_LOCAL_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>app-store-connect</string>
	<key>teamID</key>
	<string>CDMQ33VFQC</string>
	<key>uploadBitcode</key>
	<false/>
	<key>uploadSymbols</key>
	<true/>
	<key>destination</key>
	<string>export</string>
</dict>
</plist>
EOF

rm -rf "$EXPORT_LOCAL_DIR"
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_LOCAL_DIR" \
    -exportOptionsPlist "$EXPORT_LOCAL_PLIST" \
    -allowProvisioningUpdates \
    2>&1 | tail -3

IPA_PATH="$EXPORT_LOCAL_DIR/VKTurnProxy.ipa"
if [[ ! -f "$IPA_PATH" ]]; then
    fail "Expected IPA at $IPA_PATH but file not found."
    exit 1
fi
IPA_SIZE=$(stat -f%z "$IPA_PATH")
ok "IPA exported: $IPA_PATH ($IPA_SIZE bytes)"

# ─── Step 6: GitHub Release ────────────────────────────────────────────────
banner "Attaching IPA to GitHub Release $TAG"

if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release $TAG already exists; uploading IPA (--clobber overwrites prior asset of same name)"
    gh release upload "$TAG" "$IPA_PATH" --clobber
else
    # Use the tag's annotated subject as release title and its body as
    # the release notes. Falls back to a sensible default if the tag is
    # lightweight (no annotation).
    TAG_SUBJECT=$(git tag -l --format='%(contents:subject)' "$TAG")
    TAG_BODY=$(git tag -l --format='%(contents:body)' "$TAG")
    if [[ -z "$TAG_SUBJECT" ]]; then
        TAG_SUBJECT="$TAG"
    fi
    if [[ -z "$TAG_BODY" ]]; then
        TAG_BODY="Build $BUILD_NUM artifacts."
    fi
    echo "Creating release $TAG with title from tag annotation"
    gh release create "$TAG" "$IPA_PATH" \
        --title "$TAG_SUBJECT" \
        --notes "$TAG_BODY"
fi

ok "GitHub Release ready."

# ─── Summary ───────────────────────────────────────────────────────────────
RELEASE_URL=$(gh release view "$TAG" --json url -q .url 2>/dev/null || echo "")
banner "Release pipeline complete"
cat <<EOF
  Tag:         $TAG (build $BUILD_NUM)
  Archive:     $ARCHIVE_PATH
  IPA:         $IPA_PATH ($IPA_SIZE bytes)
  TestFlight:  uploaded — check App Store Connect for processing status
  GitHub:      $RELEASE_URL
EOF
