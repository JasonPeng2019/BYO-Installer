#!/bin/sh
set -eu

usage() {
  echo "usage: notarize_macos.sh <archive.zip> <bundle> <api-key.p8> <key-id> <issuer-id> <log.json>" >&2
  exit 2
}

[ "$#" -eq 6 ] || usage
archive=$1
bundle=$2
api_key=$3
key_id=$4
issuer_id=$5
log=$6

[ -f "$archive" ] && [ -d "$bundle" ] && [ -f "$api_key" ] || usage
case "$archive" in
  *.zip) ;;
  *) echo "macOS notarization requires the exact final ZIP." >&2; exit 2 ;;
esac

xcrun notarytool submit "$archive" \
  --key "$api_key" \
  --key-id "$key_id" \
  --issuer "$issuer_id" \
  --wait \
  --output-format json >"$log"

python3 -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text())
if document.get("status") != "Accepted":
    raise SystemExit(f"notarization was not accepted: {document}")
' "$log"

codesign --verify --deep --strict --verbose=2 "$bundle"
spctl --assess --type execute --verbose=2 "$bundle/byo"
spctl --assess --type execute --verbose=2 "$bundle/sidecar/byo-mcp-sidecar"
shasum -a 256 "$archive"
