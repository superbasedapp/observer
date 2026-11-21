package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestObservabilityStoreContentDefault pins the node-local Plane A content
// key (F07, D8/D17): on by default, kept on by the partial merge for an
// [observability] section that only sets enabled, and off only when the file
// says so.
func TestObservabilityStoreContentDefault(t *testing.T) {
	if !Default().Observability.StoreContent {
		t.Fatal("Default().Observability.StoreContent must be true")
	}
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"no section", "", true},
		{"section sets only enabled", "[observability]\nenabled = true\n", true},
		{"explicit false", "[observability]\nenabled = true\nstore_content = false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar})
			if err != nil {
				t.Fatal(err)
			}
			if c.Observability.StoreContent != tc.want {
				t.Errorf("StoreContent = %v, want %v", c.Observability.StoreContent, tc.want)
			}
		})
	}
}
