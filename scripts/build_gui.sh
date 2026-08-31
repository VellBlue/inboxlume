#!/bin/zsh
set -eu

PROJECT_DIR="${0:A:h:h}"
APP_DIR="$PROJECT_DIR/dist/Mail Guardian.app"
ICON_SOURCE="$PROJECT_DIR/macos/MailGuardianIcon.svg"
ICONSET_DIR="$PROJECT_DIR/build/MailGuardian.iconset"
ICON_FILE="$PROJECT_DIR/build/MailGuardianIcon.icns"
INFO_FILE="$PROJECT_DIR/build/Info.plist"
mkdir -p "$PROJECT_DIR/bin"
mkdir -p "$PROJECT_DIR/build"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"
for SIZE in 16 32 128 256 512; do
  DOUBLE_SIZE=$((SIZE * 2))
  sips -s format png -z "$SIZE" "$SIZE" "$ICON_SOURCE" \
    --out "$ICONSET_DIR/icon_${SIZE}x${SIZE}.png" >/dev/null
  sips -s format png -z "$DOUBLE_SIZE" "$DOUBLE_SIZE" "$ICON_SOURCE" \
    --out "$ICONSET_DIR/icon_${SIZE}x${SIZE}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET_DIR" -o "$ICON_FILE"
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  -framework SwiftUI \
  -framework AppKit \
  "$PROJECT_DIR/macos/MailGuardianGUI.swift" \
  -o "$PROJECT_DIR/bin/MailGuardianGUI"

mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"
cp "$PROJECT_DIR/bin/MailGuardianGUI" "$APP_DIR/Contents/MacOS/MailGuardianGUI"
cp "$PROJECT_DIR/macos/Info.plist" "$INFO_FILE"
/usr/libexec/PlistBuddy \
  -c "Set :MailGuardianProjectRoot $PROJECT_DIR" \
  "$INFO_FILE"
cp "$INFO_FILE" "$APP_DIR/Contents/Info.plist"
cp "$ICON_FILE" "$APP_DIR/Contents/Resources/MailGuardianIcon.icns"
xattr -cr "$APP_DIR"
codesign --force --deep --sign - --timestamp=none "$APP_DIR"
# Le cartelle sincronizzate di macOS possono riapplicare subito metadati Finder
# al bundle; non fanno parte dell'app e rendono fallita la verifica strict.
xattr -d com.apple.FinderInfo "$APP_DIR" 2>/dev/null || true
xattr -d 'com.apple.fileprovider.fpfs#P' "$APP_DIR" 2>/dev/null || true
codesign --verify --deep --strict "$APP_DIR"
