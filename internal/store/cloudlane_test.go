package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedExecSessions creates one project and a session per (id, location)
// pair; an empty location leaves the column NULL.
func seedExecSessions(t *testing.T, s *Store, root string, sessions [][2]string) int64 {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range sessions {
		if err := s.UpsertSession(ctx, models.Session{
			ID: p[0], ProjectID: pid, Tool: models.ToolClaudeCode,
			StartedAt: time.Date(2026, 10, 31, 10, i, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
		if p[1] != "" {
			if _, err := s.SetSessionExecution(ctx, models.SessionExecution{SessionID: p[0], ExecutionLocation: p[1]}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return pid
}

func TestLoadSessionExecutions(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedExecSessions(t, s, "/tmp/lane", [][2]string{
		{"l1", models.ExecutionLocal}, {"c1", models.ExecutionVendorCloud}, {"u1", ""},
	})
	if _, err := s.SetSessionExecution(ctx, models.SessionExecution{SessionID: "c1", VendorSessionRef: "cse_01ABC"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSessionExecutions(ctx, []string{"l1", "c1", "u1", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id      string
		present bool
		loc     string
		ref     string
	}{
		{"l1", true, "local", ""},
		{"c1", true, "vendor_cloud", "cse_01ABC"},
		{"u1", false, "", ""},      // nothing stamped: absent, never "local"
		{"missing", false, "", ""}, // no such session
	}
	for _, c := range cases {
		ex, ok := got[c.id]
		if ok != c.present || ex.ExecutionLocation != c.loc || ex.VendorSessionRef != c.ref {
			t.Errorf("%s: got %+v present=%v, want present=%v loc=%q ref=%q", c.id, ex, ok, c.present, c.loc, c.ref)
		}
	}
	empty, err := s.LoadSessionExecutions(ctx, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("nil ids: %v %v", empty, err)
	}
}

func TestLoadSessionExecutionsChunks(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	var pairs [][2]string
	var ids []string
	for i := 0; i < sessionExecutionChunk+3; i++ {
		id := fmt.Sprintf("s%04d", i)
		pairs = append(pairs, [2]string{id, models.ExecutionVendorCloud})
		ids = append(ids, id)
	}
	seedExecSessions(t, s, "/tmp/many", pairs)
	got, err := s.LoadSessionExecutions(ctx, ids)
	if err != nil || len(got) != len(ids) {
		t.Fatalf("got %d of %d, err %v", len(got), len(ids), err)
	}
}

func TestLoadProjectExecutionMix(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	stamped := seedExecSessions(t, s, "/tmp/stamped", [][2]string{
		{"a1", models.ExecutionLocal}, {"a2", models.ExecutionVendorCloud}, {"a3", models.ExecutionVendorCloud}, {"a4", ""},
	})
	plain := seedExecSessions(t, s, "/tmp/plain", [][2]string{{"b1", ""}, {"b2", ""}})
	mix, err := s.LoadProjectExecutionMix(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mix[plain]; ok {
		t.Fatalf("a project with nothing stamped must be absent: %+v", mix[plain])
	}
	want := ProjectExecutionMix{"local": 1, "vendor_cloud": 2, "": 1}
	got := mix[stamped]
	if len(got) != len(want) {
		t.Fatalf("mix = %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("mix = %+v, want %+v", got, want)
		}
	}
}

func TestListCloudUsageForSessions(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	entry := func(rec, sess string, v float64, d time.Duration) CloudUsageEntry {
		return CloudUsageEntry{
			Connector: "devin", SourceRecordID: rec,
			MeasurementSource: models.UsageSourceProviderRunTotal, ValueType: models.UsageValueDelta,
			Unit: "acu", Value: v, MonetaryStatus: models.UsageMonetaryNone,
			ScopeSession: sess, ReportedAt: at.Add(d),
		}
	}
	for _, e := range []CloudUsageEntry{
		entry("r1", "c1", 1, 0), entry("r2", "c1", 2, time.Minute), entry("r3", "c2", 3, 2*time.Minute), entry("r4", "other", 9, 0),
	} {
		if _, _, err := s.InsertCloudUsage(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	got, truncated, err := s.ListCloudUsageForSessions(ctx, []string{"c1", "c2"}, 0)
	if err != nil || truncated || len(got) != 3 {
		t.Fatalf("got %d truncated=%v err=%v", len(got), truncated, err)
	}
	if got[0].SourceRecordID != "r3" {
		t.Fatalf("newest report first, got %s", got[0].SourceRecordID)
	}
	capped, truncated, err := s.ListCloudUsageForSessions(ctx, []string{"c1", "c2"}, 2)
	if err != nil || !truncated || len(capped) != 2 {
		t.Fatalf("cap: got %d truncated=%v err=%v", len(capped), truncated, err)
	}
	none, truncated, err := s.ListCloudUsageForSessions(ctx, nil, 0)
	if err != nil || truncated || len(none) != 0 {
		t.Fatalf("no sessions: %v %v %v", none, truncated, err)
	}
}
