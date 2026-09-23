#!/usr/bin/env bash
# Release end-to-end gate, run against the packaged release artifacts.
#
# release.yml runs this on the archives build.yml produced and the publish job releases, so
# what is tested is what ships. Nothing is compiled here: the checks unpack the archives and
# drive the shipped `git-remote-enc` binary through git the way a user would.
#
# The sidecar and version checks come first and are preconditions — a mismatch means these
# are not the built artifacts, or the binary does not carry the version it will be
# published as. The rest each report and do not stop the run; the exit status is non-zero
# if any of them failed.
#
#   tests/release-e2e.sh                                  # ./dist, version not compared
#   RELEASE_TAG=v0.2.0 tests/release-e2e.sh               # what release.yml runs
#   DIST=/tmp/assets RELEASE_TAG=v0.2.0 tests/release-e2e.sh
#
# Needs: tar, gzip, sha256sum, file, git, ssh-keygen, and a Linux archive for the host
# architecture (the host-arch binary is the one actually executed; the other platforms'
# archives are checked structurally). RELEASE_TAG is required under CI.
set -euo pipefail

usage() {
  echo "usage: [DIST=<dir>] [RELEASE_TAG=vX.Y.Z] $0" >&2
  exit 2
}
[ "$#" -eq 0 ] || usage

cd "$(dirname "$0")/.."
DIST=${DIST:-dist}
[ -d "$DIST" ] || { echo "release-e2e: no artifact directory at $DIST" >&2; exit 2; }
DIST=$(cd "$DIST" && pwd)
BIN=git-remote-enc

for t in tar gzip sha256sum file git ssh-keygen; do
  command -v "$t" >/dev/null || { echo "release-e2e: $t is required" >&2; exit 2; }
done

case "$(uname -m)" in
  x86_64 | amd64) HOST_ARCH=x86_64 ;;
  aarch64 | arm64) HOST_ARCH=aarch64 ;;
  *) echo "release-e2e: no linux release archive for $(uname -m)" >&2; exit 2 ;;
esac
HOST_ARCHIVE="$DIST/$BIN-linux-$HOST_ARCH.tar.gz"

# Every platform the release publishes, so a missing archive fails the gate rather than
# going unnoticed. Keep in sync with package.sh.
PLATFORMS="linux-x86_64 linux-aarch64 macos-x86_64 macos-aarch64"

if [ -n "${CI:-}" ] && [ -z "${RELEASE_TAG:-}" ]; then
  echo "release-e2e: RELEASE_TAG is required under CI" >&2
  exit 2
fi

echo "release-e2e: testing the artifacts in $DIST"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

########################################################## preconditions

echo
echo "################ sha256 sidecars"
for p in $PLATFORMS; do
  [ -f "$DIST/$BIN-$p.tar.gz" ] || { echo "missing archive for $p" >&2; exit 1; }
  [ -f "$DIST/$BIN-$p.sha256" ] || { echo "missing sidecar for $p" >&2; exit 1; }
done
(cd "$DIST" && for s in "$BIN"-*.sha256; do sha256sum -c "$s"; done)
for a in linux-x86_64 linux-aarch64; do
  [ -f "$DIST/$BIN-$a.build-info.txt" ] || { echo "missing build manifest for $a" >&2; exit 1; }
done

echo
echo "################ archive layout"
for p in $PLATFORMS; do
  members=$(tar tzf "$DIST/$BIN-$p.tar.gz")
  for m in LICENSE README.md "$BIN"; do
    grep -qxF "$m" <<<"$members" || { echo "$p: archive lacks $m" >&2; exit 1; }
  done
  echo "$p: ok"
done

echo
echo "################ host binary"
mkdir "$WORK/bin"
tar xzf "$HOST_ARCHIVE" -C "$WORK/bin" "$BIN"
file "$WORK/bin/$BIN"
file "$WORK/bin/$BIN" | grep -q "statically linked\|static-pie" || {
  echo "the linux binary is not static" >&2; exit 1
}
version=$("$WORK/bin/$BIN" --version)
echo "$version"
if [ -n "${RELEASE_TAG:-}" ]; then
  [ "$version" = "$BIN ${RELEASE_TAG#v}" ] || {
    echo "binary reports '$version', tag is $RELEASE_TAG" >&2; exit 1
  }
fi
# The manifest's binary digest must be the binary in the archive.
expected=$(grep -E "^[0-9a-f]{64}  $BIN$" "$DIST/$BIN-linux-$HOST_ARCH.build-info.txt" | cut -d' ' -f1)
actual=$(sha256sum "$WORK/bin/$BIN" | cut -d' ' -f1)
[ "$expected" = "$actual" ] || { echo "build manifest digest $expected != archive binary $actual" >&2; exit 1; }
echo "binary matches its build manifest"

########################################################## behaviour

failures=0
check() { # <name> <command...>
  local name=$1; shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; failures=$((failures + 1)); fi
}

export PATH="$WORK/bin:$PATH"
export HOME="$WORK/home"
mkdir -p "$HOME"
git config --global user.name e2e
git config --global user.email e2e@example.com
git config --global init.defaultBranch main
export GIT_CONFIG_NOSYSTEM=1

ssh-keygen -q -t ed25519 -N '' -f "$WORK/alice" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$WORK/bob" >/dev/null

git init -q --bare "$WORK/host.git"
URL="enc::$WORK/host.git"

roundtrip() {
  git init -q "$WORK/alice-repo"
  (
    cd "$WORK/alice-repo"
    echo "hello" > README
    git add README && git commit -qm init
    git remote add enc "$URL"
    git config remote.enc.enc-identity "$WORK/alice"
    git config --add remote.enc.enc-participants "$(cat "$WORK/alice.pub")"
    git config --add remote.enc.enc-participants "$(cat "$WORK/bob.pub")"
    git push -q enc main
  )
  # First contact pins the signer, as a user would with a key obtained out of band.
  git -c "enc.identity=$WORK/bob" -c "enc.participants=$(cat "$WORK/alice.pub")" \
    clone -q "$URL" "$WORK/bob-repo"
  [ "$(cat "$WORK/bob-repo/README")" = hello ]
}
check "push and clone round trip" roundtrip

unpinned_first_contact_refused() {
  ! git -c "enc.identity=$WORK/bob" clone -q "$URL" "$WORK/bob-unpinned" 2>/dev/null
}
check "unpinned first contact refused" unpinned_first_contact_refused

host_sees_only_ciphertext() {
  [ "$(git -C "$WORK/host.git" for-each-ref --format='%(refname)')" = refs/heads/enc ] &&
    ! git -C "$WORK/host.git" grep -q hello refs/heads/enc
}
check "host sees only ciphertext" host_sees_only_ciphertext

outsider_cannot_read() {
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/carol" >/dev/null
  ! git -c "enc.identity=$WORK/carol" -c "enc.participants=$(cat "$WORK/alice.pub")" \
    clone -q "$URL" "$WORK/carol-repo" 2>/dev/null
}
check "non-participant cannot clone" outsider_cannot_read

non_ff_rejected() {
  (cd "$WORK/alice-repo" && echo a > a && git add a && git commit -qm a && git push -q enc main)
  (
    cd "$WORK/bob-repo"
    git config remote.origin.enc-identity "$WORK/bob"
    echo b > b && git add b && git commit -qm b
    ! git push -q origin main 2>/dev/null
  )
}
check "non-fast-forward push rejected" non_ff_rejected

manifest_subcommand() {
  local m
  m=$(cd "$WORK/alice-repo" && "$BIN" manifest enc)
  grep -q '^enc-manifest 2$' <<<"$m" && ! grep -q 'AGE-SECRET-KEY-' <<<"$m"
}
check "manifest subcommand" manifest_subcommand

echo
if [ "$failures" -gt 0 ]; then
  echo "release-e2e: $failures check(s) failed"
  exit 1
fi
echo "release-e2e: all checks passed"
