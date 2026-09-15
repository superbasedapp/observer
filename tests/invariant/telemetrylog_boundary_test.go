package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// telemetrylog_boundary_test.go pins the NODE import sentinel of the stateless
// collectors + durable log arc (plan of record
// docs/plans/stateless-collectors-durable-log-plan-2026-09-08.md §4.4, review
// P2-5; ADR-0006). The shared durable log is an ORG-SERVER concern: the node
// binary pushes to a collector over HTTPS exactly as before (no wire-shape
// change on the push envelope), so it must never link the log contract or any
// broker client. The guard is transitive (go list -deps) so a helper package
// that quietly gains a NATS dependency is caught, and it is non-vacuous (the
// closure must contain the entry package itself).

// logForbiddenPrefixes are the packages the node binary must never reach:
// the log contract and every broker module the org server may use.
var logForbiddenPrefixes = []string{
	modulePath + "internal/telemetrylog",
	"github.com/nats-io/",
	"github.com/twmb/franz-go",
	"github.com/segmentio/kafka-go",
}

// logNodeEntryPackages are the node-side entry points whose transitive closure
// is checked: the daemon binary, the node store, the org-push client, and the
// always-on watcher/proxy/hook paths.
var logNodeEntryPackages = []string{
	"cmd/observer",
	"internal/store",
	"internal/orgclient",
	"internal/watcher",
	"internal/proxy",
	"internal/hook",
}

// TestNodeBinaryNeverImportsTelemetryLog is the node import sentinel: the full
// transitive dependency closure of each node entry package contains neither
// internal/telemetrylog (or any subpackage) nor a broker client module.
func TestNodeBinaryNeverImportsTelemetryLog(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, entry := range logNodeEntryPackages {
		entry := entry
		t.Run(entry, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "./"+entry)
			cmd.Dir = repoRoot
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps ./%s failed: %v\n%s", entry, err, out)
			}
			var sawSelf bool
			var count int
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				pkg := strings.TrimSpace(line)
				if pkg == "" {
					continue
				}
				if pkg == modulePath+entry {
					sawSelf = true
				}
				if strings.HasPrefix(pkg, modulePath) {
					count++
				}
				for _, bad := range logForbiddenPrefixes {
					if strings.HasPrefix(pkg, bad) {
						t.Errorf("node package %q transitively imports %q — the node binary must never link "+
							"the org server's durable log contract or a broker client (stateless-collectors plan §4.4; "+
							"ADR-0006). The push wire is unchanged: the node talks HTTPS to a collector.", entry, pkg)
					}
				}
			}
			if count == 0 || !sawSelf {
				t.Fatalf("go list -deps ./%s returned an empty/self-less closure (count=%d sawSelf=%v) — the guard would be vacuous", entry, count, sawSelf)
			}
		})
	}
}

// scratchpadModulePrefix is the import-path prefix of the top-level
// scratchpad/ directory: untracked, operator-authored throwaway tooling
// (e.g. scratchpad/estateotlp, scratchpad/estateverify) that lives inside
// the module tree — so `go list ./...` finds it — but is never shipped
// code and is not subject to the node/server import-boundary rules this
// guard enforces. It is intentionally excluded below rather than deleted
// or edited (those files belong to a different, ongoing session).
var scratchpadModulePrefix = modulePath + "scratchpad/"

// TestTelemetryLogIsServerSideOnly is the direct-import half: no package
// outside internal/telemetrylog, internal/orgserver and cmd/observer-org may
// import internal/telemetrylog. Uses direct imports (test-only imports are
// excluded), so a package's own tests may still exercise the contract.
// scratchpad/ is skipped (see scratchpadModulePrefix); every other module
// package — cmd/observer, internal/store, internal/orgclient,
// internal/watcher, internal/proxy, internal/hook included — stays in
// scope.
func TestTelemetryLogIsServerSideOnly(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	cmd := exec.Command("go", "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./... failed: %v\n%s", err, out)
	}
	allowed := []string{
		modulePath + "internal/telemetrylog",
		modulePath + "internal/orgserver",
		modulePath + "cmd/observer-org",
		modulePath + "tests/invariant",
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		importer := fields[0]
		if importer == modulePath+"scratchpad" || strings.HasPrefix(importer, scratchpadModulePrefix) {
			continue
		}
		for _, imp := range fields[1:] {
			if !strings.HasPrefix(imp, modulePath+"internal/telemetrylog") {
				continue
			}
			ok := false
			for _, a := range allowed {
				if importer == a || strings.HasPrefix(importer, a+"/") {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("package %q imports %q — internal/telemetrylog is org-server-side only (ADR-0006)", importer, imp)
			}
		}
	}
}
