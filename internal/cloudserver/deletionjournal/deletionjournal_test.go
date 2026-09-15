package deletionjournal_test

import (
	"context"
	"path/filepath"
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
