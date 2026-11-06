# Notices for the bundled guest helpers

`guest-mux-linux-amd64` and `guest-mux-linux-arm64` are static Linux
executables built by `guest-mux/build.sh` from `guest-mux/guest_mux.go`, which
is part of this project and licensed under Apache 2.0 (see `LICENSE` in the
package metadata). They are compiled with Go 1.27.2 and import only the Go
standard library, which is linked into each executable.

The Go standard library is distributed under the BSD-style license in
`LICENSE-Go`, copied from the `go1.27.2` release of
<https://github.com/golang/go>.
