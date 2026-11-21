package deletionjournal_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
)

func TestFileJournalAppendReadRoundTrip(t *testing.T) {
	j, err := deletionjournal.NewFileJournal(filepath.Join(t.TempDir(), "sub", "journal.jsonl"))
	if err != nil {
		t.Fatalf("NewFileJournal: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// An empty (never-written) journal reads as zero records, not an error.
	if recs, err := j.Records(ctx); err != nil || len(recs) != 0 {
		t.Fatalf("empty journal: recs=%v err=%v", recs, err)
	}

	want := []deletionjournal.Record{
		{Event: deletionjournal.EventAccepted, AccountID: "acct-1", At: now},
		{Event: deletionjournal.EventDone, AccountID: "acct-1", RequestID: "req-1", At: now},
		{Event: deletionjournal.EventAccepted, AccountID: "acct-2", At: now},
	}
	for _, r := range want {
		if err := j.Append(ctx, r); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	got, err := j.Records(ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Event != want[i].Event || got[i].AccountID != want[i].AccountID || got[i].RequestID != want[i].RequestID || !got[i].At.Equal(want[i].At) {
			t.Fatalf("record %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// AcceptedAccounts dedupes and returns only accepted events.
	acc := deletionjournal.AcceptedAccounts(got)
	if len(acc) != 2 || acc[0] != "acct-1" || acc[1] != "acct-2" {
		t.Fatalf("AcceptedAccounts=%v, want [acct-1 acct-2]", acc)
	}
}

func TestNewFileJournalRejectsEmptyPath(t *testing.T) {
	if _, err := deletionjournal.NewFileJournal(""); err == nil {
		t.Fatal("NewFileJournal(\"\") should error")
	}
}

// TestAcceptedByKind pins the kind split (M6.9): account records feed
// deletionjournal.AcceptedAccounts, org records feed deletionjournal.AcceptedOrgs, done records feed neither,
// and a pre-kind line (no kind field) still reads as an account.
func TestAcceptedByKind(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	records := []deletionjournal.Record{
		{Event: deletionjournal.EventAccepted, AccountID: "acct-1", At: at},
		{Event: deletionjournal.EventAccepted, Kind: deletionjournal.KindOrg, OrgID: "org-1", RequestID: "r1", At: at},
		{Event: deletionjournal.EventDone, Kind: deletionjournal.KindOrg, OrgID: "org-2", At: at},
		{Event: deletionjournal.EventAccepted, Kind: deletionjournal.KindOrg, OrgID: "org-1", RequestID: "r1", At: at},
		{Event: deletionjournal.EventAccepted, Kind: deletionjournal.KindOrg, At: at}, // no org id: ignored
		{Event: deletionjournal.EventDone, AccountID: "acct-2", At: at},
	}
	if got := deletionjournal.AcceptedAccounts(records); len(got) != 1 || got[0] != "acct-1" {
		t.Errorf("deletionjournal.AcceptedAccounts = %v, want [acct-1]", got)
	}
	if got := deletionjournal.AcceptedOrgs(records); len(got) != 1 || got[0] != "org-1" {
		t.Errorf("deletionjournal.AcceptedOrgs = %v, want [org-1]", got)
	}
	var old deletionjournal.Record
	if err := json.Unmarshal([]byte(`{"event":"accepted","account_id":"a","request_id":"","at":"2026-11-16T00:00:00Z"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.Kind != deletionjournal.KindAccount {
		t.Errorf("a pre-kind line reads as kind %q, want the account kind", old.Kind)
	}
	raw, err := json.Marshal(deletionjournal.Record{Event: deletionjournal.EventAccepted, AccountID: "a", At: at})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "kind") || strings.Contains(string(raw), "org_id") {
		t.Errorf("an account record carries the org fields: %s", raw)
	}
}
