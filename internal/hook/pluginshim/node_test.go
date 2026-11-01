package pluginshim

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// shimNodeMinMajor is the oldest Node major the shim tests run under: Node
// 22, the version every Node job in ci.yml and ci-private.yml pins. The go
// test shards use the runner image's own node, so an older node there (or on
// a developer host, such as Ubuntu 20.04's packaged v10) skips with this
// reason instead of failing on syntax the shim's hosts never run (R-160).
const shimNodeMinMajor = 22

// shimNode returns a node binary new enough for the shim tests, or skips the
// test naming why.
func shimNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	out, err := exec.Command(node, "--version").Output()
	if err != nil {
		t.Skipf("node --version failed (%v); the shim tests need Node %d or newer", err, shimNodeMinMajor)
	}
	ver := strings.TrimSpace(string(out))
	if major, ok := nodeMajor(ver); !ok || major < shimNodeMinMajor {
		t.Skipf("node %s is older than Node %d, which the shim tests need; put Node %d or newer first on PATH to run them", ver, shimNodeMinMajor, shimNodeMinMajor)
	}
	return node
}

// nodeMajor reads the major version from `node --version` output ("v22.16.0").
func nodeMajor(ver string) (int, bool) {
	ver = strings.TrimPrefix(ver, "v")
	if i := strings.IndexByte(ver, '.'); i >= 0 {
		ver = ver[:i]
	}
	n, err := strconv.Atoi(ver)
	return n, err == nil
}

func TestNodeMajor(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{{"v22.16.0", 22, true}, {"v10.19.0", 10, true}, {"v24.1.0", 24, true}, {"", 0, false}, {"vX", 0, false}} {
		got, ok := nodeMajor(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("nodeMajor(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
