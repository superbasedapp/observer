//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestUpsertSecFindingRefreshesOrgKey (lane LEFT-SHARED): a re-sighting
// carrying an org_key (the node now holds the org's dedupe key, or a newer
// version of it) refreshes the stored one; a sighting without one never
// clears it.
func TestUpsertSecFindingRefreshesOrgKey(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f := secFinding("root-1", "key-1")
	id, _, err := s.UpsertSecFinding(ctx, f, now)
	if err != nil {
		t.Fatal(err)
	}
	read := func() string {
		var k string
		if err := db.QueryRowContext(ctx, `SELECT org_key FROM sec_findings WHERE id = ?`, id).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	if read() != "" {
		t.Fatal("no key held: no org_key")
	}
	f.OrgKey = "v1:" + strings.Repeat("e", 64)
	if _, _, err := s.UpsertSecFinding(ctx, f, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if read() != f.OrgKey {
		t.Fatalf("a re-sighting with a key must store it: %q", read())
	}
	f.OrgKey = ""
	if _, _, err := s.UpsertSecFinding(ctx, f, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if read() != "v1:"+strings.Repeat("e", 64) {
		t.Fatalf("a sighting without a key must not clear it: %q", read())
	}
}
