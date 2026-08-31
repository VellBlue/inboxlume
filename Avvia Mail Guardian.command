#!/bin/zsh
set -eu

PROJECT_DIR="${0:A:h}"
APP_DIR="$PROJECT_DIR/dist/Mail Guardian.app"
if [[ ! -x "$APP_DIR/Contents/MacOS/MailGuardianGUI" ]]; then
  "$PROJECT_DIR/scripts/build_gui.sh"
fi
exec open -W "$APP_DIR"
