// Package version carries the purewrt release version for runtime use
// (User-Agent strings, --version style output).
package version

// Version is stamped by the OpenWrt package build via
// `-ldflags -X github.com/purewrt/purewrt/internal/version.Version=$(PKG_VERSION)`.
// The default tracks the repo VERSION file for plain `go build` binaries —
// TestDefaultVersionMatchesVersionFile fails a release bump that forgets it.
var Version = "0.3.2"
