package cowork

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestRateLimitEvent_ChangeOnly pins the 2026-09-30 change-only capture:
// Cowork re-polls an unchanged rate-limit state several times per session
// (live corpus: 256 rows / 32 sessions, zero changes after each first),
// and each poll used to become its own "Rate limit" message row. Seven
// polls with ONE status transition (allowed -> allowed_warning) and back
// emit 1 (first) + 2 (transitions) rows, and a resumed parse after every
// line boundary makes the same decisions (seedRateLimitTracker).
func TestRateLimitEvent_ChangeOnly(t *testing.T) {
	t.Parallel()
	src := fixturePath(t, "cowork-aaaa/dev-bbbb")
	root := t.TempDir()
	dst := filepath.Join(root, "cowork-aaaa", "dev-bbbb")
	if err := os.MkdirAll(filepath.Join(dst, "local_cccc-dddd-eeee"), 0o755); err != nil {
		t.Fatal(err)
	}
	sidecar, err := os.ReadFile(filepath.Join(src, "local_cccc-dddd-eeee.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "local_cccc-dddd-eeee.json"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	statuses := []string{"allowed", "allowed", "allowed", "allowed_warning", "allowed_warning", "allowed", "allowed"}
	var lines []string
	for i, st := range statuses {
		lines = append(lines, fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":%q,"resetsAt":1772546400,"rateLimitType":"five_hour","overageStatus":"rejected","isUsingOverage":false},"uuid":"url-%04d","session_id":"s","_audit_timestamp":%q}`,
			st, i, t0.Add(time.Duration(i)*time.Minute).Format("2006-01-02T15:04:05.000Z")))
	}
	body := strings.Join(lines, "\n") + "\n"
	audit := filepath.Join(dst, "local_cccc-dddd-eeee", "audit.jsonl")
	if err := os.WriteFile(audit, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, root)
	rlIDs := func(res adapter.ParseResult) []string {
		var out []string
		for _, ev := range res.ToolEvents {
			if ev.ActionType == models.ActionRateLimit {
				out = append(out, ev.SourceEventID)
			}
		}
		return out
	}
	full, err := a.ParseSessionFile(context.Background(), audit, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	got := rlIDs(full)
	want := []string{"url-0000", "url-0003", "url-0005"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rate_limit rows %v, want %v (first + 2 status transitions of %d polls)", got, want, len(statuses))
	}
	offset := int64(0)
	for li := range lines {
		offset += int64(len(lines[li]) + 1)
		tail, err := a.ParseSessionFile(context.Background(), audit, offset)
		if err != nil {
			t.Fatalf("resume at %d: %v", offset, err)
		}
		var wantTail []string
		for _, id := range want {
			var n int
			if _, err := fmt.Sscanf(id, "url-%d", &n); err == nil && n > li {
				wantTail = append(wantTail, id)
			}
		}
		if g := rlIDs(tail); strings.Join(g, ",") != strings.Join(wantTail, ",") {
			t.Errorf("resume after line %d: %v, want %v", li+1, g, wantTail)
		}
	}
}
