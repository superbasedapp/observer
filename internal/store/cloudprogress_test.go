package store

import (
	"context"
	"fmt"
	"testing"
)

func TestLoadCloudEnrichmentProgress(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	const before = "2026-09-14T10:00:00Z"
	const resultAt = "2026-09-14T10:00:00.5Z"
	const after = "2026-09-14T10:01:00Z"
	type request struct{ state, created, updated string }
	cases := []struct {
		name     string
		result   bool
		requests []request
		want     string
	}{
		{"idle", false, nil, "idle"},
		{"queued", false, []request{{"pending", before, before}}, "pending"},
		{"uploading", false, []request{{"sending", before, before}}, "sending"},
		{"upload is not completion", false, []request{{"sent", before, before}}, "sent"},
		{"retry", false, []request{{"failed_retryable", before, before}}, "failed_retryable"},
		{"review", false, []request{{"reconfirmation_required", before, before}}, "reconfirmation_required"},
		{"failed", false, []request{{"failed_terminal", before, before}}, "failed_terminal"},
		{"cancelled", false, []request{{"cancelled", before, before}}, "cancelled"},
		{"result resolves sent history", true, []request{{"sent", before, before}}, "complete"},
		{"reconfirmed old row awaits result", true, []request{{"sent", before, after}}, "sent"},
		{"new upload retains older result", true, []request{{"sent", before, before}, {"pending", after, after}}, "pending"},
		{"new sent awaits new result", true, []request{{"sent", after, after}}, "sent"},
		{"live upload survives result pull", true, []request{{"pending", before, before}}, "pending"},
		{"old review does not hide result", true, []request{{"reconfirmation_required", before, before}}, "complete"},
		{"history does not hide active request", false, []request{{"pending", before, before}, {"cancelled", after, after}}, "pending"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := fmt.Sprintf("progress-%d", i)
			seedEligibleSession(t, s, id)
			for n, req := range tc.requests {
				_, err := database.ExecContext(ctx, `INSERT INTO cloud_outbox
					(id, session_id, evidence_content_digest, upload_digest, receipt_id, state, created_at, updated_at, last_error)
					VALUES (?, ?, 'evidence', 'upload', 'receipt', ?, ?, ?, 'http_429')`,
					fmt.Sprintf("%s-%d", id, n), id, req.state, req.created, req.updated)
				if err != nil {
					t.Fatal(err)
				}
			}
			if tc.result {
				if _, err := s.UpsertCloudResult(ctx, CloudResult{SessionID: id, SchemaVersion: "v1", ResultJSON: `{"title":"Previous result"}`, ReceivedAt: cloudParseTime(resultAt)}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.LoadCloudEnrichmentProgress(ctx, []string{id, "missing"})
			if err != nil {
				t.Fatal(err)
			}
			if got[id] == nil || got[id].State != tc.want {
				t.Fatalf("progress = %+v, want %s", got[id], tc.want)
			}
			if tc.want == "failed_retryable" && got[id].LastError != "http_429" {
				t.Fatal("retry reason was lost")
			}
			if got["missing"] != nil {
				t.Fatal("unknown session acquired progress")
			}
		})
	}
	t.Run("empty and chunked lookup", func(t *testing.T) {
		if got, err := s.LoadCloudEnrichmentProgress(ctx, nil); err != nil || len(got) != 0 {
			t.Fatalf("empty = %v, %v", got, err)
		}
		ids := make([]string, cloudEnrichedTitlesChunkSize+1)
		for i := range ids {
			ids[i] = fmt.Sprintf("absent-%d", i)
		}
		ids[0], ids[len(ids)-1] = "progress-0", "progress-1"
		got, err := s.LoadCloudEnrichmentProgress(ctx, ids)
		if err != nil || len(got) != 2 {
			t.Fatalf("chunked = %v, %v", got, err)
		}
	})
}
