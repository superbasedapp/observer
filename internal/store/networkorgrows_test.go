package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// seedNetworkEvent persists one network_connect event through the real
// PersistProcessEvents write path (mirroring processobs_test.go's own
// seeding style), optionally attaching a body.
func seedNetworkEvent(t *testing.T, s *Store, sessionID, processKey string, ts time.Time, details map[string]any, body *processobs.NetworkBodyCapture) {
	t.Helper()
	ev := processobs.ProcessEvent{
		ProcessKey: processKey,
		Timestamp:  ts,
		Type:       processobs.EventNetworkConnect,
		Attribution: processobs.Attribution{
			SessionID:  sessionID,
			Source:     processobs.AttrHeuristic,
			Confidence: processobs.ConfMedium,
		},
		TargetKind:  "url",
		Target:      "https://api.example.test/v1/messages",
		Severity:    "info",
		Details:     details,
		NetworkBody: body,
	}
	if _, err := s.PersistProcessEvents(context.Background(), []processobs.ProcessEvent{ev}); err != nil {
		t.Fatalf("seedNetworkEvent: PersistProcessEvents: %v", err)
	}
}

func TestSelectSessionNetworkEvents_ProxyEventWithBody(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	started := time.Now().UTC().Add(-time.Hour)

	seedNetworkEvent(t, s, sessionID, "proxy:aaa", started,
		map[string]any{
			"capture_source": "proxy",
			"provider":       "anthropic",
			"method":         "POST",
			"url":            "https://api.example.test/v1/messages",
			"host":           "api.example.test",
			"status_code":    200,
			"duration_ms":    321,
			"stream":         true,
		},
		&processobs.NetworkBodyCapture{
			CaptureSource:         "proxy",
			RequestID:             "req_abc",
			Method:                "POST",
			URL:                   "https://api.example.test/v1/messages",
			Host:                  "api.example.test",
			StatusCode:            200,
			DurationMs:            321,
			RequestBody:           `{"model":"claude"}`,
			RequestBodySHA256:     "reqhash",
			RequestBodyBytes:      19,
			ResponseBody:          `{"id":"msg_1"}`,
			ResponseBodySHA256:    "resphash",
			ResponseBodyBytes:     14,
			ResponseContentType:   "application/json",
			ResponseBodyTruncated: true,
		})

	rows, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.SessionID != sessionID {
		t.Fatalf("SessionID = %q, want %q", r.SessionID, sessionID)
	}
	if r.EventKey == "" || r.RunKey != "proxy:aaa" {
		t.Fatalf("EventKey/RunKey = %q/%q, want non-empty key + run key proxy:aaa", r.EventKey, r.RunKey)
	}
	if r.CaptureSource != "proxy" || r.Provider != "anthropic" || r.Method != "POST" || r.URL == "" || r.Host != "api.example.test" {
		t.Fatalf("HTTP-shaped fields not populated: %+v", r)
	}
	if r.StatusCode != 200 || r.DurationMs != 321 || !r.Stream {
		t.Fatalf("numeric/bool HTTP fields wrong: %+v", r)
	}
	if !r.HasBody {
		t.Fatalf("HasBody = false, want true")
	}
	if r.RequestBody == "" || r.RequestBodySHA256 != "reqhash" || r.RequestBodyBytes != 19 {
		t.Fatalf("request body fields wrong: %+v", r)
	}
	if r.ResponseBody == "" || !r.ResponseBodyTruncated || r.ResponseContentType != "application/json" {
		t.Fatalf("response body fields wrong: %+v", r)
	}
	// Socket-shaped fields must stay zero for a proxy-sourced row.
	if r.Protocol != "" || r.RemoteAddr != "" || r.BytesIn != 0 {
		t.Fatalf("socket-shaped fields leaked onto a proxy row: %+v", r)
	}
}

func TestSelectSessionNetworkEvents_OSObservedNoBody(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	started := time.Now().UTC().Add(-time.Hour)

	seedNetworkEvent(t, s, sessionID, "os:bbb", started,
		map[string]any{
			"capture_source":            "process_backend",
			"protocol":                  "tcp",
			"family":                    "inet",
			"remote_addr":               "1.2.3.4",
			"remote_port":               443,
			"local_addr":                "10.0.0.5",
			"local_port":                51000,
			"status":                    "established",
			"bytes_in":                  1024,
			"bytes_out":                 512,
			"body_unavailable_reason":   "metadata_only_non_plaintext",
			"payload_capture_supported": false,
		}, nil)

	rows, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.HasBody {
		t.Fatalf("HasBody = true, want false for an OS-observed event")
	}
	if r.CaptureSource != "process_backend" || r.Protocol != "tcp" || r.RemoteAddr != "1.2.3.4" || r.RemotePort != 443 {
		t.Fatalf("socket-shaped fields wrong: %+v", r)
	}
	if r.NetworkStatus != "established" || r.BytesIn != 1024 || r.BytesOut != 512 {
		t.Fatalf("status/byte fields wrong: %+v", r)
	}
	if r.BodyUnavailableReason != "metadata_only_non_plaintext" {
		t.Fatalf("BodyUnavailableReason = %q, want metadata_only_non_plaintext (the honesty rule)", r.BodyUnavailableReason)
	}
	// HTTP-shaped fields must stay zero for an OS-observed row.
	if r.Method != "" || r.URL != "" || r.StatusCode != 0 {
		t.Fatalf("HTTP-shaped fields leaked onto an OS-observed row: %+v", r)
	}
}

func TestSelectSessionNetworkEvents_ExcludesUnattributedAndOldEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	// In-window, attributed to a session: included.
	seedNetworkEvent(t, s, sessionID, "os:recent", now.Add(-time.Hour),
		map[string]any{"capture_source": "process_backend"}, nil)
	// Older than the trailing window: excluded.
	seedNetworkEvent(t, s, sessionID, "os:old", now.AddDate(0, 0, -sessionNetworkWindowDays-1),
		map[string]any{"capture_source": "process_backend"}, nil)
	// No session attribution at all: PersistProcessEvents stores session_id
	// NULL, so the WHERE session_id IS NOT NULL AND != '' filter drops it.
	if _, err := s.PersistProcessEvents(ctx, []processobs.ProcessEvent{{
		ProcessKey: "os:unattributed",
		Timestamp:  now.Add(-time.Minute),
		Type:       processobs.EventNetworkConnect,
		TargetKind: "network_endpoint",
		Target:     "5.6.7.8:443",
		Details:    map[string]any{"capture_source": "process_backend"},
	}}); err != nil {
		t.Fatalf("seed unattributed event: %v", err)
	}

	rows, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(rows) != 1 || rows[0].RunKey != "os:recent" {
		t.Fatalf("rows = %+v, want exactly the one in-window attributed event", rows)
	}
}

func TestSelectSessionNetworkEvents_NoEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	rows, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0 on an empty store", len(rows))
	}
}

func TestSelectSessionNetworkEvents_CapsPerSessionMostRecent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	// Seed one more than the cap; the oldest must be the one dropped.
	total := sessionNetworkEventCap + 3
	for i := 0; i < total; i++ {
		ts := now.Add(-time.Duration(total-i) * time.Second)
		seedNetworkEvent(t, s, sessionID, "os:many", ts,
			map[string]any{"capture_source": "process_backend"}, nil)
	}

	rows, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(rows) != sessionNetworkEventCap {
		t.Fatalf("rows = %d, want cap %d", len(rows), sessionNetworkEventCap)
	}
	// The kept rows must be the MOST RECENT ones: the earliest timestamp
	// among the kept rows should be strictly after the very first seeded one.
	oldest := rows[0].Timestamp
	for _, r := range rows {
		if r.Timestamp < oldest {
			oldest = r.Timestamp
		}
	}
	firstSeeded := timestamp(now.Add(-time.Duration(total) * time.Second))
	if oldest == firstSeeded {
		t.Fatalf("cap kept the oldest event (%q); want most-recent-first retention", firstSeeded)
	}
}

func TestSelectSessionNetworkEventsBounded_CapsAcrossSessionsByBytes(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		seedNetworkEvent(t, s, sessionID, "proxy:bounded", now.Add(time.Duration(i)*time.Second),
			map[string]any{"capture_source": "proxy", "method": "POST"},
			&processobs.NetworkBodyCapture{CaptureSource: "proxy", RequestBody: "request-body", ResponseBody: "response-body"})
	}

	all, err := s.SelectSessionNetworkEvents(ctx)
	if err != nil {
		t.Fatalf("SelectSessionNetworkEvents: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("unbounded rows = %d, want 3", len(all))
	}

	rows, err := s.SelectSessionNetworkEventsBounded(ctx, jsonSize(all[0]))
	if err != nil {
		t.Fatalf("SelectSessionNetworkEventsBounded: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("bounded rows = %d, want exactly 1", len(rows))
	}
}

// Envelope-budget sentinel for the 2026-08-26 incident: the COMPOSED
// SelectUnpushedSince batch — not just each slice — must respect maxBytes.
// Before the bound, seven days of request/response bodies rode every push
// tick in full (233 MB compressed against a 1 MiB limit), ballooning the
// daemon heap and re-materialising on each auth-failure retry.
func TestSelectUnpushedSince_NetworkEventsRespectEnvelopeBudget(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	body := strings.Repeat("x", 64<<10)
	for i := 0; i < 20; i++ {
		seedNetworkEvent(t, s, sessionID, "proxy:budget", now.Add(time.Duration(i)*time.Second),
			map[string]any{"capture_source": "proxy", "method": "POST"},
			&processobs.NetworkBodyCapture{CaptureSource: "proxy", RequestBody: body, ResponseBody: body})
	}

	const maxBytes = 1 << 20
	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, maxBytes, "o", "u",
		ShareOptions{AdminManaged: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if n := len(batch.SessionNetworkEvents); n == 0 || n >= 20 {
		t.Fatalf("network events = %d, want a truncated non-empty subset of 20", n)
	}
	if batch.EstBytes > maxBytes {
		t.Fatalf("EstBytes = %d exceeds maxBytes = %d", batch.EstBytes, maxBytes)
	}

	// A roomy budget still carries the complete snapshot.
	wide, err := s.SelectUnpushedSince(ctx, PushCursor{}, 64<<20, "o", "u",
		ShareOptions{AdminManaged: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (wide): %v", err)
	}
	if len(wide.SessionNetworkEvents) != 20 {
		t.Fatalf("wide budget network events = %d, want 20", len(wide.SessionNetworkEvents))
	}
}
