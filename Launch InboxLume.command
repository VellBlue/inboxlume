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

project_dir="${0:A:h}"
python_path="$project_dir/.venv/bin/python"
app_dir="$project_dir/dist/InboxLume.app"

environment_ready=false
if [[ -x "$python_path" ]]; then
    export PYTHONPATH="$project_dir/src"
    site_packages=$("$python_path" -c \
        'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null || true)
    if [[ -n "$site_packages" && -d "$site_packages" ]]; then
        # Alcune cartelle sincronizzate marcano wheel e file .pth come hidden.
        # Python e Qt possono quindi ignorare moduli o plugin perfettamente
        # presenti. Ripristinare il flag non modifica contenuti o credenziali.
        # ``path`` is tied to ``PATH`` in zsh: naming the loop variable that
        # would replace the command search path with a file name, and every
        # later command resolved by name would stop being found.
        for pth_file in "$site_packages"/*.pth(N); do
            /usr/bin/chflags nohidden "$pth_file" 2>/dev/null || true
        done
        if [[ -d "$site_packages/PySide6/Qt" ]]; then
            /usr/bin/chflags -R nohidden \
                "$site_packages/PySide6/Qt" 2>/dev/null || true
        fi
    fi
    if "$python_path" "$project_dir/scripts/check_desktop_environment.py" \
        "$project_dir"; then
        environment_ready=true
    fi
fi

if [[ "$environment_ready" != true ]]; then
    echo "L'ambiente desktop locale è assente, obsoleto o non supportato."
    echo "Il dettaglio è nelle righe che iniziano con \"-\" qui sopra."
    echo "InboxLume richiede Python 3.11, 3.12 o 3.13 (non Python 3.14)."
    echo "Esegui una volta:"
    echo "  cd \"$project_dir\""
    echo "  python3.13 -m venv .venv"
    echo "  source .venv/bin/activate"
    echo "  python -m pip install -e '.[desktop]'"
    echo
    echo "Se manca l'archivio certificati TLS, nessun provider è verificabile"
    echo "finché non installi le CA radice per quel Python. Con una"
    echo "installazione da python.org esegui una volta:"
    echo "  \"/Applications/Python 3.13/Install Certificates.command\""
    read -k 1 "?Premi un tasto per chiudere…"
    echo
    exit 1
fi

if [[ ! -x "$app_dir/Contents/MacOS/InboxLume" \
    || "$project_dir/macos/InboxLumeLauncher.sh" -nt "$app_dir/Contents/MacOS/InboxLume" \
    || "$project_dir/macos/InboxLume-Info.plist" -nt "$app_dir/Contents/Info.plist" \
    || "$project_dir/.venv/pyvenv.cfg" -nt "$app_dir/Contents/MacOS/InboxLume" ]]; then
    "$project_dir/scripts/build_inboxlume_app.sh"
fi
# I metadati del provider di sincronizzazione possono ricomparire dopo la
# firma. Rimuoverli immediatamente prima dell'apertura mantiene verificabile il
# bundle senza alterarne alcun file applicativo.
xattr -cr "$app_dir"
/usr/bin/chflags -R nohidden "$app_dir"
xattr -d com.apple.FinderInfo "$app_dir" 2>/dev/null || true
xattr -d 'com.apple.fileprovider.fpfs#P' "$app_dir" 2>/dev/null || true
if ! codesign --verify --deep --strict "$app_dir"; then
    "$project_dir/scripts/build_inboxlume_app.sh"
fi
exec open -W "$app_dir"
