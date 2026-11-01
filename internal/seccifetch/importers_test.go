package seccifetch

import (
	"os/exec"
	"strings"
	"testing"
)

// TestOnlyTheVerifyCommandLinksTheFetch pins the egress lane
// security.ci.fetch to its one trigger: within the node binary, the only
// package importing this one is cmd/observer (its verify files), so no
// daemon path (watcher, proxy, store, hook, the security service) can reach
// the org's CI routes.
func TestOnlyTheVerifyCommandLinksTheFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the go toolchain")
	}
	const self = "github.com/marmutapp/superbased-observer/internal/seccifetch"
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}\t{{join .Imports \",\"}}", "../../cmd/observer").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	var importers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg, imports, _ := strings.Cut(line, "\t")
		for _, imp := range strings.Split(imports, ",") {
			if imp == self {
				importers = append(importers, pkg)
			}
		}
	}
	if len(importers) != 1 || importers[0] != "github.com/marmutapp/superbased-observer/cmd/observer" {
		t.Fatalf("internal/seccifetch is imported by %v; only cmd/observer (the verify command) may link it", importers)
	}
}
