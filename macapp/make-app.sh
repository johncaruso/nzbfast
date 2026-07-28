#!/bin/bash
# Build NzbFast.app - the WKWebView wrapper that owns the bundled
# nzbfast engine (packaging/INSTALLER-SPEC.md, chip A).
#
#   ./make-app.sh                    universal wrapper + universal engine
#   ENGINE=/path/to/nzbfast ./make-app.sh   reuse a prebuilt engine binary
#
# Version source of truth is crates/nzbfast/Cargo.toml (shared rule 8).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

VERSION=$(grep '^version' "$REPO/crates/nzbfast/Cargo.toml" | head -1 | cut -d'"' -f2)
echo "== NzbFast.app v$VERSION"

# --- engine: universal binary via the release lipo recipe -------------
if [ -z "${ENGINE:-}" ]; then
    echo "== building universal engine"
    (cd "$REPO" && cargo build --release \
        --target aarch64-apple-darwin --target x86_64-apple-darwin -p nzbfast)
    ENGINE="$REPO/target/nzbfast-universal"
    lipo -create -output "$ENGINE" \
        "$REPO/target/aarch64-apple-darwin/release/nzbfast" \
        "$REPO/target/x86_64-apple-darwin/release/nzbfast"
fi
lipo -info "$ENGINE"

# --- wrapper: universal SwiftPM build ---------------------------------
echo "== building wrapper"
swift build -c release --arch arm64 --arch x86_64
WRAPPER=.build/apple/Products/Release/NzbFast

# --- assemble the bundle ----------------------------------------------
APP=build/NzbFast.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
cp "$WRAPPER" "$APP/Contents/MacOS/NzbFast"
cp "$ENGINE" "$APP/Contents/Resources/bin/nzbfast"
chmod +x "$APP/Contents/Resources/bin/nzbfast"

# Icon: iconset from the committed 1024px master (packaging/icon/).
ICONSET=$(mktemp -d)/NzbFast.iconset
mkdir -p "$ICONSET"
for entry in 16:icon_16x16 32:icon_16x16@2x 32:icon_32x32 64:icon_32x32@2x \
             128:icon_128x128 256:icon_128x128@2x 256:icon_256x256 \
             512:icon_256x256@2x 512:icon_512x512 1024:icon_512x512@2x; do
    size=${entry%%:*}; name=${entry#*:}
    sips -z "$size" "$size" "$REPO/packaging/icon/icon-1024.png" \
        --out "$ICONSET/$name.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/NzbFast.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>NzbFast</string>
  <key>CFBundleDisplayName</key><string>nzbfast</string>
  <key>CFBundleIdentifier</key><string>com.nzbfast.app</string>
  <key>CFBundleExecutable</key><string>NzbFast</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleIconFile</key><string>NzbFast</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key><true/>
  </dict>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key><string>NZB file</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>LSHandlerRank</key><string>Default</string>
      <key>LSItemContentTypes</key><array><string>com.nzbfast.nzb</string></array>
    </dict>
  </array>
  <key>UTImportedTypeDeclarations</key>
  <array>
    <dict>
      <key>UTTypeIdentifier</key><string>com.nzbfast.nzb</string>
      <key>UTTypeDescription</key><string>NZB file</string>
      <key>UTTypeConformsTo</key><array><string>public.xml</string></array>
      <key>UTTypeTagSpecification</key>
      <dict>
        <key>public.filename-extension</key><array><string>nzb</string></array>
      </dict>
    </dict>
  </array>
</dict>
</plist>
PLIST

# --- ad-hoc sign, inside-out ------------------------------------------
# arm64 refuses unsigned Mach-Os, and lipo output loses the linker's
# ad-hoc signature - sign the nested engine FIRST, then the app, so the
# outer seal covers the signed payload (signing can later be swapped for
# a real identity without restructuring).
codesign --force -s - "$APP/Contents/Resources/bin/nzbfast"
codesign --force -s - "$APP"
codesign --verify --deep --strict "$APP"

echo "built $APP (v$VERSION)"
