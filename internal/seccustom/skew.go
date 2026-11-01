package seccustom

import (
	"fmt"
	"strconv"
	"strings"
)

// GoToolchainFormat is the version format of a companion that reports a Go
// toolchain version (the "go" row of the closed version format table).
const GoToolchainFormat = "go"

// ToolchainSkew is what the skew check found: Skewed when the executable
// is a Go program built with an older Go release than the Go toolchain a
// companion reports, and Detail one plain sentence saying so.
type ToolchainSkew struct {
	Skewed bool   `json:"skewed"`
	Detail string `json:"detail,omitempty"`
}

// CheckToolchainSkew compares builtWith, the Go release the executable was
// built with ("go1.26.3"; "" when it is not a Go program or could not be
// read), with the version every companion of the go version format
// reported (versions, keyed by companion path). A Go analyzer built with an
// older release than the toolchain it loads packages with can silently
// skip checks (JSP-12: gosec built with Go 1.26 drops G104, G702 and G703
// against Go 1.27), so a skewed run never counts as complete. An unknown
// version on either side is no skew: the self-test is what catches the
// rest.
func CheckToolchainSkew(builtWith string, m Manifest, versions map[string]string) ToolchainSkew {
	built, ok := goMinor(builtWith)
	if !ok {
		return ToolchainSkew{}
	}
	for _, c := range m.Companions {
		if c.VersionFormat != GoToolchainFormat {
			continue
		}
		tc, ok := goMinor(versions[c.Path])
		if !ok || !olderMinor(built, tc) {
			continue
		}
		return ToolchainSkew{Skewed: true, Detail: fmt.Sprintf(
			"the scanner was built with Go %d.%d and the go companion is Go %d.%d: a Go analyzer built with an older Go release can silently skip checks, so this run is never complete",
			built[0], built[1], tc[0], tc[1])}
	}
	return ToolchainSkew{}
}

// goMinor reads the major and minor release of a Go version in either of
// its spellings ("go1.27.2", "1.27", "go1.27rc1").
func goMinor(v string) ([2]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return [2]int{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return [2]int{}, false
	}
	minorText := parts[1]
	for i, r := range minorText {
		if r < '0' || r > '9' {
			minorText = minorText[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return [2]int{}, false
	}
	return [2]int{major, minor}, true
}

func olderMinor(a, b [2]int) bool {
	return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1])
}
