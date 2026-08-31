#!/bin/zsh
set -eu

# LaunchServices can start this bundle translated by Rosetta, and every child
# process then inherits x86_64.  MLX ships no x86_64 build, so all local model
# profiles would be reported unavailable on a Mac that fully supports them, and
# the main action would stay disabled with a message blaming the hardware.
# The marker makes the re-exec run at most once.
if [[ "${INBOXLUME_NATIVE_REEXEC:-}" != "1" \
    && "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null)" == "1" ]]; then
    export INBOXLUME_NATIVE_REEXEC=1
    exec /usr/bin/arch -arm64 "$0" "$@"
fi

bundle_dir="${0:A:h:h}"
project_dir=$(/usr/libexec/PlistBuddy -c "Print :InboxLumeProjectRoot" "$bundle_dir/Info.plist")
python_path="$project_dir/.venv/bin/python"

if [[ ! -x "$python_path" ]]; then
    /usr/bin/osascript -e 'display alert "InboxLume non è pronto" message "L’ambiente Python locale non è disponibile. Avvia prima “Launch InboxLume.command” dalla cartella del progetto." as critical'
    exit 1
fi

export PYTHONPATH="$project_dir/src"
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
if ! "$python_path" "$project_dir/scripts/check_desktop_environment.py" \
    "$project_dir" >/dev/null 2>&1; then
    /usr/bin/osascript -e 'display alert "InboxLume non è pronto" message "Il venv non è coerente o usa una versione Python non supportata. Ricrealo con Python 3.11, 3.12 o 3.13 tramite “Launch InboxLume.command”." as critical'
    exit 1
fi
qt_libraries=$("$python_path" -c \
    'from PySide6.QtCore import QLibraryInfo; print(QLibraryInfo.path(QLibraryInfo.LibraryPath.LibrariesPath))')
qt_plugins="$bundle_dir/Resources/Qt/plugins"
/usr/bin/chflags -R nohidden "$bundle_dir/Resources/Qt" 2>/dev/null || true
if [[ ! -f "$qt_plugins/platforms/libqcocoa.dylib" || ! -d "$qt_libraries" ]]; then
    /usr/bin/osascript -e 'display alert "InboxLume non è pronto" message "Il runtime grafico Qt non è disponibile. Ricrea InboxLume.app con Launch InboxLume.command." as critical'
    exit 1
fi
export DYLD_FRAMEWORK_PATH="$qt_libraries"
export QT_PLUGIN_PATH="$qt_plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$qt_plugins/platforms"
exec "$python_path" -m inboxlume.desktop_app
