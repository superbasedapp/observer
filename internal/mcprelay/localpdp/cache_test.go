package localpdp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
)

func TestSiblingPath(t *testing.T) {
	if got := SiblingPath("/home/u/.observer/org-policy-bundle.json", "/x/observer.db"); got != "/home/u/.observer/mcp-node-table.json" {
		t.Fatalf("got %s", got)
	}
	if got := SiblingPath("", "/x/observer.db"); got != "/x/mcp-node-table.json" {
		t.Fatalf("got %s", got)
	}
}

// TestCacheRoundTrip: Save then Load yields an equivalent table (mode, meta,
// rows, audit-strict marks, grant index); absent and corrupt files are
// typed failures, never a fabricated table.
func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := Cache{Path: filepath.Join(dir, "sub", CacheFileName)}
	if _, err := c.Load(); !errors.Is(err, ErrCacheAbsent) {
		t.Fatalf("absent: %v", err)
	}
	tbl, err := Compile(famcp.PolicySpec{Mode: famcp.ModeEnforce, Spec: productSpec()}, Meta{Version: 7, BodyHash: "bh", OrgKey: "ok", Generation: 2, EnforceAllowed: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tbl.AuditStrict = map[string]bool{"vs-gh": true}
	if err := c.Save(tbl); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache perm %o, want owner-only", st.Mode().Perm())
	}
	got, err := c.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != ModeEnforce || got.Meta != tbl.Meta || len(got.Node.Rows) != len(tbl.Node.Rows) || !got.AuditStrict["vs-gh"] {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got.Grants["g-any-ask"].AuditClass != "strict" || got.PolicyGen() != 1 {
		t.Fatalf("grant index / policy gen not rebuilt: %+v", got.Grants)
	}
	if got.Node.Rows[0].Grant.Effect != mcpaccess.EffectAsk {
		t.Fatalf("row order not preserved (deny > ask > allow): %+v", got.Node.Rows[0].Grant)
	}
	if err := os.WriteFile(c.Path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load(); err == nil || errors.Is(err, ErrCacheAbsent) {
		t.Fatalf("corrupt cache must be an error: %v", err)
	}
	if err := os.WriteFile(c.Path, []byte(`{"format":99,"table":{"mode":"enforce"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Load(); err == nil {
		t.Fatal("foreign format must be an error")
	}
	if err := c.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(); err != nil {
		t.Fatalf("remove must be idempotent: %v", err)
	}
	if err := (Cache{Path: c.Path}).Save(nil); err == nil {
		t.Fatal("nil table must be refused")
	}
}
