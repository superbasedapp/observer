package otelident

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports keeps the vocabulary data only, importable by
// every plane and build.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/obs",
			"github.com/marmutapp/superbased-observer/internal/store",
			"go.opentelemetry.io",
		},
		Reason: "internal/otelident is a data-only vocabulary",
	})
}

// TestHostedAppKeys: the union is tenant then user keys, with no duplicate,
// and callers cannot mutate the owner's lists through it.
func TestHostedAppKeys(t *testing.T) {
	got := HostedAppKeys()
	if len(got) != len(TenantKeys)+len(UserKeys) {
		t.Fatalf("HostedAppKeys = %v", got)
	}
	seen := map[string]bool{}
	for _, k := range got {
		if seen[k] {
			t.Fatalf("duplicate key %q", k)
		}
		seen[k] = true
	}
	got[0] = "mutated"
	if TenantKeys[0] == "mutated" {
		t.Fatal("HostedAppKeys aliases TenantKeys")
	}
}
