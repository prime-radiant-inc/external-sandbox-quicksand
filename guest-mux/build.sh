#!/bin/sh
# Rebuild the bundled guest transport helpers from guest_mux.go.
# The pinned toolchain reproduces the committed binaries byte for byte.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../src/external_sandbox_quicksand/guest_bin"
mkdir -p "$out"
for arch in arm64 amd64; do
  GOTOOLCHAIN=go1.27.2 CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
    go build -trimpath -ldflags '-s -w' -o "$out/guest-mux-linux-$arch" "$here/guest_mux.go"
done
shasum -a 256 "$out"/guest-mux-linux-*
