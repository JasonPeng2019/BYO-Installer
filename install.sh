#!/bin/sh
set -eu

usage() {
  echo "usage:" >&2
  echo "  ./install.sh --bundle <byo-archive-or-extracted-bundle> [--install-dir <absolute-path>]" >&2
  echo "  ./install.sh --version <exact> --base-url <https-url> --sha256 <hex> [--public-key <ed25519-public.pem>] [--install-dir <absolute-path>]" >&2
  exit 2
}

bundle=
version=
base_url=
expected_sha=
public_key=
install_dir=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) [ "$#" -ge 2 ] || usage; bundle=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2 ;;
    --base-url) [ "$#" -ge 2 ] || usage; base_url=$2; shift 2 ;;
    --sha256) [ "$#" -ge 2 ] || usage; expected_sha=$2; shift 2 ;;
    --public-key) [ "$#" -ge 2 ] || usage; public_key=$2; shift 2 ;;
    --install-dir) [ "$#" -ge 2 ] || usage; install_dir=$2; shift 2 ;;
    *) usage ;;
  esac
done

system=$(uname -s)
machine=$(uname -m)
case "$system" in
  Darwin) product_platform=macos ;;
  Linux) product_platform=linux ;;
  *) echo "This bootstrap supports macOS and Linux; use install.ps1 on Windows." >&2; exit 2 ;;
esac
case "$machine" in
  x86_64|amd64) product_arch=x86_64 ;;
  arm64|aarch64) product_arch=aarch64 ;;
  *) echo "Unsupported CPU architecture: $machine" >&2; exit 2 ;;
esac

temporary=
# shellcheck disable=SC2329 # Invoked indirectly by the trap below.
cleanup() {
  if [ -n "$temporary" ] && [ -d "$temporary" ]; then
    rm -rf -- "$temporary"
  fi
}
trap cleanup EXIT HUP INT TERM

make_temporary() {
  if [ -z "$temporary" ]; then
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/byo-install.XXXXXXXX")
  fi
}

extract_archive() {
  candidate_archive=$1
  extraction_destination=$2
  if [ "$product_platform" = "macos" ]; then
    bundle_root=$(/usr/bin/zipinfo -1 "$candidate_archive" | awk '
      BEGIN { bad = 0; count = 0; top = ""; has_child = 0 }
      {
        path = $0
        sub(/\/$/, "", path)
        count++
        lowered = tolower(path)
        parts_count = split(path, parts, "/")
        if (path == "" || path ~ /^\// || path ~ /\/\// || path ~ /\\/ ||
            path ~ /(^|\/)\.\.?($|\/)/ || path ~ /^[A-Za-z]:/ ||
            seen[lowered]++) {
          bad = 1
        }
        if (top == "") {
          top = parts[1]
        } else if (top != parts[1]) {
          bad = 1
        }
        if (parts_count > 1) {
          has_child = 1
        }
      }
      END {
        if (count == 0 || count > 20000 || top == "" || !has_child) bad = 1
        if (bad) exit 1
        print top
      }
    ') || {
      echo "ZIP archive contains an unsafe, duplicate, excessive, or multi-root path set." >&2
      exit 21
    }
    /usr/bin/zipinfo -l "$candidate_archive" | awk '
      BEGIN { bad = 0 }
      $1 ~ /^[bclps-]/ && substr($1, 1, 1) != "-" { bad = 1 }
      END { exit bad }
    ' || { echo "ZIP archive contains a forbidden non-file entry." >&2; exit 21; }
    /usr/bin/ditto -x -k "$candidate_archive" "$extraction_destination"
  else
    bundle_root=$(tar -tzf "$candidate_archive" | awk '
      BEGIN { bad = 0; count = 0; top = ""; has_child = 0 }
      {
        path = $0
        sub(/\/$/, "", path)
        count++
        lowered = tolower(path)
        parts_count = split(path, parts, "/")
        if (path == "" || path ~ /^\// || path ~ /\/\// || path ~ /\\/ ||
            path ~ /(^|\/)\.\.?($|\/)/ || path ~ /^[A-Za-z]:/ ||
            seen[lowered]++) {
          bad = 1
        }
        if (top == "") {
          top = parts[1]
        } else if (top != parts[1]) {
          bad = 1
        }
        if (parts_count > 1) {
          has_child = 1
        }
      }
      END {
        if (count == 0 || count > 20000 || top == "" || !has_child) bad = 1
        if (bad) exit 1
        print top
      }
    ') || {
      echo "Archive contains an unsafe, duplicate, excessive, or multi-root path set." >&2
      exit 21
    }
    tar -tvzf "$candidate_archive" | awk '
      BEGIN { bad = 0 }
      $1 ~ /^[bchlps-]/ && substr($1, 1, 1) != "-" { bad = 1 }
      END { exit bad }
    ' || { echo "Archive contains a forbidden non-file entry." >&2; exit 21; }
    tar -xzf "$candidate_archive" -C "$extraction_destination" --no-same-owner --no-same-permissions
  fi
  [ -d "$extraction_destination/$bundle_root" ] || {
    echo "Archive did not create its declared bundle directory." >&2
    exit 21
  }
}

verify_downloaded_platform_signature=0
if [ -z "$bundle" ]; then
  [ -n "$version" ] && [ -n "$base_url" ] && [ -n "$expected_sha" ] || usage
  case "$version" in *[!0-9A-Za-z.+-]*|'') echo "Invalid exact version." >&2; exit 2 ;; esac
  case "$base_url" in https://*) ;; *) echo "The release base URL must use HTTPS." >&2; exit 2 ;; esac
  case "$expected_sha" in
    *[!0-9a-fA-F]*|'') echo "The SHA-256 digest is invalid." >&2; exit 2 ;;
  esac
  [ "${#expected_sha}" -eq 64 ] || { echo "The SHA-256 digest is invalid." >&2; exit 2; }

  if [ "$product_platform" = "macos" ]; then
    archive_extension=zip
  else
    archive_extension=tar.gz
  fi
  archive_name="byo-$version-$product_platform-$product_arch.$archive_extension"
  archive_url="${base_url%/}/$archive_name"
  make_temporary
  archive="$temporary/$archive_name"
  curl --fail --location --proto '=https' --tlsv1.2 --output "$archive" "$archive_url"

  if command -v shasum >/dev/null 2>&1; then
    actual_sha=$(shasum -a 256 "$archive" | awk '{print $1}')
  elif command -v sha256sum >/dev/null 2>&1; then
    actual_sha=$(sha256sum "$archive" | awk '{print $1}')
  else
    echo "No SHA-256 verifier is installed." >&2
    exit 2
  fi
  [ "$actual_sha" = "$(printf '%s' "$expected_sha" | tr 'A-F' 'a-f')" ] || {
    echo "Downloaded archive SHA-256 mismatch." >&2
    exit 23
  }

  if [ "$product_platform" = "linux" ]; then
    [ -n "$public_key" ] && [ -f "$public_key" ] || {
      echo "Linux network installation requires --public-key for the detached Ed25519 signature." >&2
      exit 23
    }
    signature="$temporary/$archive_name.sig"
    curl --fail --location --proto '=https' --tlsv1.2 --output "$signature" "$archive_url.sig"
    openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -sigfile "$signature" -in "$archive" >/dev/null || {
      echo "Downloaded archive signature verification failed." >&2
      exit 23
    }
  fi
  bundle=$archive
  verify_downloaded_platform_signature=1
fi

if [ -f "$bundle" ]; then
  case "$product_platform:$bundle" in
    macos:*.zip|linux:*.tar.gz) ;;
    macos:*) echo "macOS bundle archives must use the .zip format." >&2; exit 2 ;;
    linux:*) echo "Linux bundle archives must use the .tar.gz format." >&2; exit 2 ;;
  esac
  archive=$bundle
  make_temporary
  extraction_root="$temporary/extracted"
  mkdir -p "$extraction_root"
  extract_archive "$archive" "$extraction_root"
  bundle="$extraction_root/$bundle_root"
elif [ ! -d "$bundle" ]; then
  echo "Bundle path is not an archive or extracted directory: $bundle" >&2
  exit 2
fi

launcher="$bundle/byo"
[ -f "$launcher" ] || { echo "Bundle launcher is missing: $launcher" >&2; exit 2; }

if [ -n "$install_dir" ]; then
  case "$install_dir" in
    /*) ;;
    *) install_dir="$(pwd)/$install_dir" ;;
  esac
fi

if [ "$verify_downloaded_platform_signature" -eq 1 ] && [ "$product_platform" = "macos" ]; then
  codesign --verify --deep --strict --verbose=2 "$bundle"
  spctl --assess --type execute --verbose=2 "$launcher"
fi

if [ -n "$install_dir" ]; then
  "$launcher" install-runtime --bundle "$bundle" --install-dir "$install_dir"
else
  "$launcher" install-runtime --bundle "$bundle"
fi
status=$?
if [ "$status" -eq 0 ]; then
  echo "BYO installed. If 'byo' is not found in a new shell, add the bin path reported by 'byo paths' to PATH."
fi
exit "$status"
