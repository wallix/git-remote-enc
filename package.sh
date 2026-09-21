#!/usr/bin/env bash
# Build a deterministic release archive for a compiled git-remote-enc binary.
#
# The archive contains the binary at its root plus README.md and LICENSE. Outputs:
#
#   dist/git-remote-enc-<platform>.tar.gz
#   dist/git-remote-enc-<platform>.sha256   one sha256sum line naming that archive
#
# Member order, ownership, modes, and timestamps are fixed. All platforms are
# packaged on Linux to use the same GNU tar/gzip implementation.
#
# Usage:
#   ./package.sh --platform <name> --binary <path> [--out <dir>]
#
# Flags also accept --flag=value. Paths are relative to the repository root.
#
#   --platform  one of the release matrix names: linux-x86_64, linux-aarch64,
#               macos-x86_64, macos-aarch64
#   --binary    the compiled binary to package
#   --out       directory to write the archive and sidecar to (default: dist)
#
# Archive bytes depend on the archiver. dist/git-remote-enc.sha256 covers only the
# binary and is the reproducibility reference.
set -euo pipefail
cd "$(dirname "$0")"

BIN_NAME=git-remote-enc
EPOCH=0
PLATFORMS="linux-x86_64 linux-aarch64 macos-x86_64 macos-aarch64"

PLATFORM=""
BINARY=""
OUT=dist
# Report missing option values before shift fails under set -e.
need_val() { [ "$2" -ge 2 ] || { echo "package.sh: $1 needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
  case "$1" in
    # Reject empty values before the =* cases.
    --platform=|--binary=|--out=) echo "package.sh: ${1%=} needs a value" >&2; exit 2 ;;
    --platform) need_val "$1" $#; PLATFORM="$2"; shift 2 ;;
    --platform=*) PLATFORM="${1#*=}"; shift ;;
    --binary) need_val "$1" $#; BINARY="$2"; shift 2 ;;
    --binary=*) BINARY="${1#*=}"; shift ;;
    --out) need_val "$1" $#; OUT="$2"; shift 2 ;;
    --out=*) OUT="${1#*=}"; shift ;;
    *) echo "package.sh: unknown argument: $1 (--platform, --binary, --out)" >&2; exit 2 ;;
  esac
done

# Validate inputs before creating output.
[ -n "$PLATFORM" ] || { echo "package.sh: --platform is required (one of: $PLATFORMS)" >&2; exit 2; }
[ -n "$BINARY" ] || { echo "package.sh: --binary is required" >&2; exit 2; }
case " $PLATFORMS " in
  *" $PLATFORM "*) ;;
  *) echo "package.sh: unknown platform '$PLATFORM' (one of: $PLATFORMS)" >&2; exit 2 ;;
esac
[ -f "$BINARY" ] || { echo "package.sh: no binary at $BINARY" >&2; exit 1; }
# Check archivers before replacing an existing archive.
for t in tar gzip sha256sum; do
  command -v "$t" >/dev/null || { echo "package.sh: $t is required" >&2; exit 1; }
done

STEM="$BIN_NAME-$PLATFORM"
ARCHIVE="$STEM.tar.gz"
SIDECAR="$STEM.sha256"

# Stage only the files included in the release archive.
STAGE=$(mktemp -d)
TMP_ARCHIVE=""
TMP_SIDECAR=""
trap 'rm -rf "$STAGE"; rm -f "$TMP_ARCHIVE" "$TMP_SIDECAR"' EXIT
install -m 0755 "$BINARY" "$STAGE/$BIN_NAME"
install -m 0644 README.md LICENSE "$STAGE/"
find "$STAGE" -exec touch -h -d "@$EPOCH" {} +

mkdir -p "$OUT"
OUT_ABS=$(cd "$OUT" && pwd)
# List members explicitly in a fixed order.
MEMBERS=(LICENSE README.md "$BIN_NAME")
# Publish the archive and sidecar only after both are complete.
TMP_ARCHIVE="$OUT_ABS/.$ARCHIVE.tmp"
TMP_SIDECAR="$OUT_ABS/.$SIDECAR.tmp"
# gzip -n leaves out the name and mtime a .gz header would otherwise carry.
tar --format=gnu --no-recursion --owner=0 --group=0 --numeric-owner \
  --mtime="@$EPOCH" -cf - -C "$STAGE" "${MEMBERS[@]}" \
  | gzip -9n > "$TMP_ARCHIVE"

# The binary must sit at the archive root.
tar tzf "$TMP_ARCHIVE" | grep -qxF "$BIN_NAME" || {
  echo "package.sh: $ARCHIVE has no $BIN_NAME at its root:" >&2
  tar tzf "$TMP_ARCHIVE" >&2
  exit 1
}
# The sidecar uses the bare archive name for sha256sum -c compatibility.
digest=$(sha256sum "$TMP_ARCHIVE" | cut -d' ' -f1)
printf '%s  %s\n' "$digest" "$ARCHIVE" > "$TMP_SIDECAR"
mv -f "$TMP_ARCHIVE" "$OUT_ABS/$ARCHIVE"
mv -f "$TMP_SIDECAR" "$OUT_ABS/$SIDECAR"
echo "package.sh: wrote $OUT/$ARCHIVE" >&2
cat "$OUT_ABS/$SIDECAR" >&2
