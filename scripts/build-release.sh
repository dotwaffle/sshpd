#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || $1 != /* || ! $2 =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo 'Usage: build-release.sh ABSOLUTE_OUTPUT_DIR VERSION' >&2
  exit 1
fi

release_dir=$1
release_version=$2
mkdir -p "$release_dir"
printf 'platform\tsshpd_bytes\tsshpc_bytes\tarchive_bytes\n' > "$release_dir/sizes.tsv"

for target in linux/amd64 linux/arm64 darwin/amd64 freebsd/amd64; do
  target_os=${target%/*}
  target_arch=${target#*/}
  archive_name="sshpd_${release_version}_${target_os}_${target_arch}.tar.gz"
  build_dir=$(mktemp -d "$release_dir/.build.XXXXXX")
  trap 'rm -rf "$build_dir"' EXIT

  for binary in sshpd sshpc; do
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$build_dir/$binary" "./cmd/$binary"
  done
  cp README.md "$build_dir/README.md"
  cp examples/sshpd.json "$build_dir/sshpd.example.json"
  printf 'version: %s\nrevision: %s\nplatform: %s\ntoolchain: %s\n' "$release_version" "${SOURCE_REVISION:-unknown}" "$target" "$(go version)" > "$build_dir/BUILDINFO"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C "$build_dir" -czf "$release_dir/$archive_name" sshpd sshpc README.md sshpd.example.json BUILDINFO
  printf '%s\t%s\t%s\t%s\n' "$target" "$(stat -c %s "$build_dir/sshpd")" "$(stat -c %s "$build_dir/sshpc")" "$(stat -c %s "$release_dir/$archive_name")" >> "$release_dir/sizes.tsv"
  rm -rf "$build_dir"
  trap - EXIT
done

(
  cd "$release_dir"
  sha256sum "sshpd_${release_version}_"*.tar.gz > SHA256SUMS
  cat sizes.tsv
)
