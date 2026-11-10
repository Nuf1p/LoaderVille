#!/usr/bin/env bash
# restore.sh — put the pristine app.asar back (undo deploy.sh).
#
# Usage: ./restore.sh [RESOURCES_DIR|GLOB ...]
#   Same target syntax as deploy.sh. Every matched dir that carries an
#   app.asar.orig.bak is restored. No argument -> the default glob
#   /mnt/c/Users/*/AppData/Local/Discord/app-*/resources.
set -euo pipefail

cd "$(dirname "$0")"

DEFAULT_GLOB='/mnt/c/Users/*/AppData/Local/Discord/app-*/resources'

# --- resolve target resources dirs (restore every match that has a backup) ---
dirs=()
for arg in "$@"; do
  if [ -d "$arg" ]; then
    dirs+=("$arg")
  else
    hit=0
    while IFS= read -r m; do dirs+=("$m"); hit=1; done < <(compgen -G "$arg" || true)
    [ "$hit" -eq 0 ] && echo "note     : no match for '$arg'" >&2
  fi
done
if [ "$#" -eq 0 ]; then
  while IFS= read -r m; do dirs+=("$m"); done < <(compgen -G "$DEFAULT_GLOB" || true)
fi
if [ "${#dirs[@]}" -eq 0 ]; then
  echo "no resources dir matched — pass the dir containing the backdoored .asar" >&2
  exit 1
fi

restored=0
for d in "${dirs[@]}"; do
  if [ ! -f "$d/app.asar.orig.bak" ]; then
    echo "skip     : $d (no app.asar.orig.bak — nothing to restore)"
    continue
  fi
  cp "$d/app.asar.orig.bak" "$d/app.asar"
  echo "restored : $d/app.asar (sha256 $(sha256sum "$d/app.asar" | cut -c1-16)…)"
  rm -rf "$d/app.asar.unpacked/node_modules/@koromix"
  echo "cleaned  : $d/app.asar.unpacked/node_modules/@koromix"
  restored=$((restored + 1))
done

if [ "$restored" -eq 0 ]; then
  echo "nothing restored — no backup found in any matched dir" >&2
  exit 1
fi
echo "note     : backups kept as app.asar.orig.bak; delete them for pristine dirs"
