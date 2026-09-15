package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHandleCloudDigestsAllProjects pins the no-`project` default: every
// digest on this device is returned, newest period first.
func TestHandleCloudDigestsAllProjects(t *testing.T) {
	s, database := newCloudTestServer(t)
	st := store.New(database)
	ctx := context.Background()

	if err := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID: "digest-1", CloudProjectID: "cp_abc", LocalProjectID: "1",
		PeriodStart: "2026-09-01", PeriodEnd: "2026-09-07",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"first"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest (1): %v", err)
	}
	if err := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID: "digest-2", CloudProjectID: "cp_abc", LocalProjectID: "1",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"second"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest (2): %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleCloudDigests(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/digests", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudDigestsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Digests) != 2 {
		t.Fatalf("digests = %d, want 2: %+v", len(resp.Digests), resp.Digests)
	}
	// Newest period first.
	if resp.Digests[0].ID != "digest-2" || resp.Digests[1].ID != "digest-1" {
		t.Fatalf("ordering wrong: %+v", resp.Digests)
	}
	if string(resp.Digests[0].Result) != `{"headline":"second"}` {
		t.Errorf("result body not passed through raw: %s", resp.Digests[0].Result)
	}
}

// TestHandleCloudDigestsScopedByProjectRoot pins the `project` query param:
// it names a project ROOT PATH (the same convention every other dashboard
// filter uses), resolved via store.ProjectIDForRoot, and scopes the listing
// to that project's own digests only.
func TestHandleCloudDigestsScopedByProjectRoot(t *testing.T) {
	s, database := newCloudTestServer(t)
	st := store.New(database)
	ctx := context.Background()

	pid, err := st.UpsertProject(ctx, "/home/dev/repo-a", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	local := strconv.FormatInt(pid, 10)

	if err := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID: "digest-a", CloudProjectID: "cp_a", LocalProjectID: local,
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"repo-a"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest (a): %v", err)
	}
	// A digest for an unrelated project must not show up in the scoped
	// listing.
	if err := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID: "digest-b", CloudProjectID: "cp_b", LocalProjectID: "999",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"repo-b"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest (b): %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleCloudDigests(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/digests?project=/home/dev/repo-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudDigestsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Digests) != 1 || resp.Digests[0].ID != "digest-a" {
		t.Fatalf("scoped digests = %+v, want exactly digest-a", resp.Digests)
	}
}

// TestHandleCloudDigestsUnknownProjectIsEmptyNotError pins the honest
// degrade: a project root this device has never seen resolves to an empty
// list, never a 4xx/5xx — the routine case for a project with no digests
// (or no agent activity) yet.
func TestHandleCloudDigestsUnknownProjectIsEmptyNotError(t *testing.T) {
	s, _ := newCloudTestServer(t)
	rr := httptest.NewRecorder()
	s.handleCloudDigests(rr, httptest.NewRequest(http.MethodGet, "/api/cloud/digests?project=/never/seen", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp CloudDigestsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Digests) != 0 {
		t.Fatalf("digests = %+v, want empty", resp.Digests)
	}
}
