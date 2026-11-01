package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sealTestRun(id string) TerminalRun {
	return TerminalRun{
		RunID: id, Tool: "claude-code", Kind: "pty", LaunchedAt: time.Now().UTC(),
		Isolation: TerminalRunIsolation{Class: "process", EvidenceDigest: strings.Repeat("d", 64), EvidenceProducer: "terminal_run"},
	}
}

func dumpTerminalRun(t *testing.T, s *Store, id string) string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT * FROM terminal_run WHERE run_id = ?`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	if !rows.Next() {
		t.Fatal("no row")
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for i, c := range cols {
		if c != "launched_at" {
			m[c] = vals[i]
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// TestTerminalRunSealSeam: with no sealer the row is byte-identical to
// the row the insert wrote before the seal existed (every seal column ”),
// and the wire row carries no seal; with one, the seal is stored and rides
// on the wire row, nothing else changes; a sealer that cannot seal leaves
// the run unsealed.
func TestTerminalRunSealSeam(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.InsertTerminalRun(ctx, sealTestRun("run-a")); err != nil {
		t.Fatal(err)
	}
	plain := dumpTerminalRun(t, s, "run-a")
	for _, c := range []string{`"evidence_seal_key_id":""`, `"evidence_seal_public_key":""`, `"evidence_seal_sig":""`} {
		if !strings.Contains(plain, c) {
			t.Fatalf("nil sealer wrote a seal: %s", plain)
		}
	}
	s.SetTerminalRunSealer(func(context.Context, string) (TerminalRunSeal, bool) { return TerminalRunSeal{}, false })
	if err := s.InsertTerminalRun(ctx, sealTestRun("run-b")); err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(dumpTerminalRun(t, s, "run-b"), "run-b", "run-a"); got != plain {
		t.Fatalf("a sealer that cannot seal changed the row:\n%s\n%s", got, plain)
	}
	var seen string
	s.SetTerminalRunSealer(func(_ context.Context, digest string) (TerminalRunSeal, bool) {
		seen = digest
		return TerminalRunSeal{KeyID: "k1", PublicKey: "pub", Sig: "sig"}, true
	})
	t.Cleanup(func() { s.SetTerminalRunSealer(nil) })
	if err := s.InsertTerminalRun(ctx, sealTestRun("run-c")); err != nil {
		t.Fatal(err)
	}
	if seen != strings.Repeat("d", 64) {
		t.Fatalf("sealer saw %q", seen)
	}
	sealed := dumpTerminalRun(t, s, "run-c")
	want := strings.NewReplacer(`"evidence_seal_key_id":""`, `"evidence_seal_key_id":"k1"`, `"evidence_seal_public_key":""`, `"evidence_seal_public_key":"pub"`,
		`"evidence_seal_sig":""`, `"evidence_seal_sig":"sig"`, "run-a", "run-c").Replace(plain)
	if sealed != want {
		t.Fatalf("the seal changed another column:\n%s\n%s", sealed, want)
	}
	rows, err := s.SelectTerminalRunRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		b, _ := json.Marshal(r)
		switch r.RunID {
		case "run-c":
			if r.EvidenceSeal == nil || r.EvidenceSeal.KeyID != "k1" {
				t.Errorf("sealed wire row: %s", b)
			}
		default:
			if r.EvidenceSeal != nil || strings.Contains(string(b), "evidence_seal") {
				t.Errorf("unsealed wire row carries a seal: %s", b)
			}
		}
	}
}
