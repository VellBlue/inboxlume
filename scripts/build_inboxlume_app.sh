#!/bin/zsh
set -eu

project_dir="${0:A:h:h}"
app_dir="$project_dir/dist/InboxLume.app"
python_path="$project_dir/.venv/bin/python"
icon_source="$project_dir/macos/InboxLumeIcon.png"
iconset_dir="$project_dir/build/InboxLume.iconset"
icon_file="$project_dir/build/InboxLumeIcon.icns"
info_file="$project_dir/build/InboxLume-Info.plist"

if [[ ! -x "$python_path" ]]; then
    echo "Ambiente Python InboxLume non disponibile: $python_path" >&2
    exit 1
fi
export PYTHONPATH="$project_dir/src"
if ! "$python_path" "$project_dir/scripts/check_desktop_environment.py" \
    "$project_dir"; then
    echo "Ambiente Python InboxLume non valido; usa Python 3.11-3.13" >&2
    exit 1
fi
qt_plugins_source=$("$python_path" -c \
    'from PySide6.QtCore import QLibraryInfo; print(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath))')
if [[ ! -d "$qt_plugins_source/platforms" ]]; then
    echo "Plugin Qt di piattaforma non disponibili" >&2
    exit 1
fi

mkdir -p "$project_dir/build"
rm -rf "$iconset_dir"
mkdir -p "$iconset_dir"
for size in 16 32 128 256 512; do
    double_size=$((size * 2))
    sips -s format png -z "$size" "$size" "$icon_source" \
        --out "$iconset_dir/icon_${size}x${size}.png" >/dev/null
    sips -s format png -z "$double_size" "$double_size" "$icon_source" \
        --out "$iconset_dir/icon_${size}x${size}@2x.png" >/dev/null
done
python3 "$project_dir/scripts/build_icns.py" "$iconset_dir" "$icon_file"

mkdir -p "$app_dir/Contents/MacOS"
mkdir -p "$app_dir/Contents/Resources"
rm -rf "$app_dir/Contents/Resources/Qt"
mkdir -p "$app_dir/Contents/Resources/Qt"
cp -R "$qt_plugins_source" "$app_dir/Contents/Resources/Qt/plugins"
cp "$project_dir/macos/InboxLumeLauncher.sh" "$app_dir/Contents/MacOS/InboxLume"
chmod 755 "$app_dir/Contents/MacOS/InboxLume"
cp "$project_dir/macos/InboxLume-Info.plist" "$info_file"
/usr/libexec/PlistBuddy \
    -c "Set :InboxLumeProjectRoot $project_dir" \
    "$info_file"
cp "$info_file" "$app_dir/Contents/Info.plist"
cp "$icon_file" "$app_dir/Contents/Resources/InboxLumeIcon.icns"
xattr -cr "$app_dir"
/usr/bin/chflags -R nohidden "$app_dir"
codesign --force --deep --sign - --timestamp=none "$app_dir"
# Alcune cartelle sincronizzate riapplicano immediatamente metadati Finder al
# bundle o ai plugin copiati. Non fanno parte dell'app e farebbero fallire la
# verifica strict.
xattr -cr "$app_dir"
/usr/bin/chflags -R nohidden "$app_dir"
xattr -d com.apple.FinderInfo "$app_dir" 2>/dev/null || true
xattr -d 'com.apple.fileprovider.fpfs#P' "$app_dir" 2>/dev/null || true
codesign --verify --deep --strict "$app_dir"
