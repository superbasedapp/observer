//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
)

// The change records are the security module's (sbo_omit_security compiles
// them out), so their test lives apart from the terminal-run seal test
// (R-008).

// TestListChangeRecordsBeforePages (audit finding F8): the keyset pages walk
// a repository's records newest first without a gap or a repeat.
func TestListChangeRecordsBeforePages(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		r := ChangeRecordRow{
			ProjectRootHash: "root", CommitSHA: strings.Repeat(string(rune('a'+i)), 40), RecordDigest: strings.Repeat(string(rune('a'+i)), 64),
			Envelope: []byte("{}"), RecordedAt: "2026-10-2" + string(rune('0'+i)) + "T00:00:00Z",
		}
		if _, err := s.InsertChangeRecord(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	at, id := "", int64(0)
	for {
		page, err := s.ListChangeRecordsBefore(ctx, "root", at, id, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			seen = append(seen, r.CommitSHA[:1])
		}
		if len(page) < 2 {
			break
		}
		at, id = page[len(page)-1].RecordedAt, page[len(page)-1].ID
	}
	if strings.Join(seen, "") != "edcba" {
		t.Fatalf("pages read %v, want newest first, each once", seen)
	}
	if other, _ := s.ListChangeRecordsBefore(ctx, "another-root", "", 0, 10); len(other) != 0 {
		t.Fatal("another repository's records leaked")
	}
}
