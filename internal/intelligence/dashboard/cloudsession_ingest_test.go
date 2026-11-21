package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

func newCloudSessionServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database})
	if err != nil {
		t.Fatal(err)
	}
	return s, database
}

// confirmed returns a POST with a valid double-submit confirm token.
func confirmed(t *testing.T, s *Server, path, body string) *http.Request {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleCloudSessionTokens(rr, httptest.NewRequest(http.MethodGet, "/api/cloud-session/tokens", nil))
	var list struct {
		Confirm string `json:"confirm_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeader, list.Confirm)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func mintNodeShipToken(t *testing.T, s *Server, body string) (secret, id string) {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleCloudSessionTokens(rr, confirmed(t, s, "/api/cloud-session/tokens", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("mint = %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Token string            `json:"token"`
		View  nodeShipTokenView `json:"ship_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || resp.View.Status != shiptoken.StatusActive {
		t.Fatalf("mint response %s", rr.Body.String())
	}
	return resp.Token, resp.View.TokenID
}

func nodeShip(t *testing.T, s *Server, authz string, env orgcontract.PushEnvelope) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(env)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	req := httptest.NewRequest(http.MethodPost, cloudSessionIngestRoute, &buf)
	req.Header.Set("Content-Encoding", "gzip")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rr := httptest.NewRecorder()
	s.handleCloudSessionIngest(rr, req)
	return rr
}

func nodeShipEnvelope() orgcontract.PushEnvelope {
	return orgcontract.PushEnvelope{
		CursorTo: 3,
		Sessions: []orgcontract.SessionRow{{
			ID: "cse-n1", Tool: "claude-code", GitRemote: "https://github.com/acme/repo.git",
			ExecutionLocation: "vendor_cloud", VendorSessionRef: "cse_N1",
		}},
		Actions: []orgcontract.ActionRow{{
			SessionID: "cse-n1", SourceEventID: "e1", Timestamp: "2026-10-31T10:00:01Z",
			Tool: "claude-code", ActionType: "read_file", Success: true,
		}},
		TokenUsage: []orgcontract.TokenUsageRow{{
			SessionID: "cse-n1", SourceEventID: "t1", Timestamp: "2026-10-31T10:00:02Z",
			Tool: "claude-code", Model: "claude-sonnet-4", InputTokens: 10, OutputTokens: 2, Source: "jsonl", Reliability: "approximate",
		}},
		Deletions: []orgcontract.PushDeletion{{Table: "actions", SessionID: "local-session", SourceEventID: "x"}},
	}
}

// TestNodeCloudSessionIngestOffByDefault: with no token minted the route
// does not exist, whatever the request carries.
func TestNodeCloudSessionIngestOffByDefault(t *testing.T) {
	s, _ := newCloudSessionServer(t)
	other, _ := shiptoken.Generate(bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	for _, authz := range []string{"", "Bearer " + other.Token} {
		if rr := nodeShip(t, s, authz, nodeShipEnvelope()); rr.Code != http.StatusNotFound {
			t.Fatalf("no token minted, authz %q: %d, want 404", authz, rr.Code)
		}
	}
}

// TestNodeCloudSessionIngestRoundTrip: mint, ship, the session lands on the
// local project with its execution stamp; refusals by token state.
func TestNodeCloudSessionIngestRoundTrip(t *testing.T) {
	s, database := newCloudSessionServer(t)
	secret, id := mintNodeShipToken(t, s, `{"label":"tailscale"}`)

	rr := nodeShip(t, s, "Bearer "+secret, nodeShipEnvelope())
	if rr.Code != http.StatusOK {
		t.Fatalf("ship = %d %s", rr.Code, rr.Body.String())
	}
	var rcpt shiptoken.Receipt
	_ = json.Unmarshal(rr.Body.Bytes(), &rcpt)
	if rcpt.TokenRowsRemaining == nil || *rcpt.TokenRowsRemaining != shiptoken.NodeRowCap-2 || rcpt.SkippedSessions != nil {
		t.Fatalf("receipt capacity %s", rr.Body.String())
	}
	if rcpt.AcceptedRows != 2 || rcpt.DroppedRows["deletions"] != 1 || rcpt.NextCursor != 3 {
		t.Fatalf("receipt %s", rr.Body.String())
	}
	var loc, ref, root string
	if err := database.QueryRow(`SELECT s.execution_location, s.vendor_session_ref, p.root_path
		FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'cse-n1'`).Scan(&loc, &ref, &root); err != nil {
		t.Fatal(err)
	}
	if loc != "vendor_cloud" || ref != "cse_N1" || root != "cloud:github.com/acme/repo" {
		t.Fatalf("landed (%s, %s, %s)", loc, ref, root)
	}

	for _, tc := range []struct {
		name, authz string
		code        string
	}{
		{"missing", "", shiptoken.CodeMissing},
		{"not a ship token", "Bearer abc.def", shiptoken.CodeInvalid},
		{"unknown", "Bearer " + strings.Replace(secret, secret[len(secret)-4:], "AAAA", 1), shiptoken.CodeInvalid},
	} {
		if rr := nodeShip(t, s, tc.authz, nodeShipEnvelope()); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), tc.code) {
			t.Errorf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
	}

	// Expiry, then revocation.
	if _, err := database.Exec(`UPDATE cloud_session_ship_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE token_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	live, liveID := mintNodeShipToken(t, s, `{"label":"second env"}`)
	if rr := nodeShip(t, s, "Bearer "+secret, nodeShipEnvelope()); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), shiptoken.CodeExpired) {
		t.Fatalf("expired: %d %s", rr.Code, rr.Body.String())
	}
	rv := httptest.NewRecorder()
	s.handleCloudSessionToken(rv, confirmed(t, s, "/api/cloud-session/tokens/"+liveID+"/revoke", `{}`))
	if rv.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rv.Code, rv.Body.String())
	}
	// With every token expired or revoked the route is gone again.
	if rr := nodeShip(t, s, "Bearer "+live, nodeShipEnvelope()); rr.Code != http.StatusNotFound {
		t.Fatalf("after the last token was revoked: %d", rr.Code)
	}
	// Revoke needs the confirm token.
	bad := httptest.NewRequest(http.MethodPost, "/api/cloud-session/tokens/"+liveID+"/revoke", strings.NewReader(`{}`))
	bad.Header.Set("Content-Type", "application/json")
	br := httptest.NewRecorder()
	s.handleCloudSessionToken(br, bad)
	if br.Code != http.StatusForbidden {
		t.Fatalf("revoke without confirm = %d", br.Code)
	}
	// The list never carries the secret or its hash.
	lr := httptest.NewRecorder()
	s.handleCloudSessionTokens(lr, httptest.NewRequest(http.MethodGet, "/api/cloud-session/tokens", nil))
	if strings.Contains(lr.Body.String(), secret) || strings.Contains(lr.Body.String(), shiptoken.Hash(secret)) || !strings.Contains(lr.Body.String(), `"use_count":1`) {
		t.Fatalf("list %s", lr.Body.String())
	}
}

// TestNodeCloudSessionMintNeedsConfirm: the mint is an owner-local write
// behind the double-submit confirm token.
func TestNodeCloudSessionMintNeedsConfirm(t *testing.T) {
	s, _ := newCloudSessionServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/cloud-session/tokens", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleCloudSessionTokens(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mint without confirm = %d", rr.Code)
	}
	bad := httptest.NewRecorder()
	s.handleCloudSessionTokens(bad, confirmed(t, s, "/api/cloud-session/tokens", `{"label":"a\nb"}`))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad label = %d", bad.Code)
	}
}

// TestNodeCloudSessionPerEnvironment pins decision CA-D18 on the node: the
// label names a cloud environment and is required, one active token per
// environment, the list shows the time left, and a landed session is tagged
// with the token that reported it.
func TestNodeCloudSessionPerEnvironment(t *testing.T) {
	s, database := newCloudSessionServer(t)
	for _, body := range []string{`{}`, `{"label":"  "}`} {
		rr := httptest.NewRecorder()
		s.handleCloudSessionTokens(rr, confirmed(t, s, "/api/cloud-session/tokens", body))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("mint %s = %d %s", body, rr.Code, rr.Body.String())
		}
	}
	secret, id := mintNodeShipToken(t, s, `{"label":"web env"}`)
	// CA-D19: the node destination is the owner's own, full content by default.
	mr := httptest.NewRecorder()
	s.handleCloudSessionTokens(mr, confirmed(t, s, "/api/cloud-session/tokens", `{"label":"posture env"}`))
	if mr.Code != http.StatusOK || !strings.Contains(mr.Body.String(), `"share_posture":"full_content"`) {
		t.Fatalf("node mint posture = %d %s", mr.Code, mr.Body.String())
	}
	dup := httptest.NewRecorder()
	s.handleCloudSessionTokens(dup, confirmed(t, s, "/api/cloud-session/tokens", `{"label":"WEB ENV"}`))
	if dup.Code != http.StatusConflict {
		t.Fatalf("second token for one environment = %d %s", dup.Code, dup.Body.String())
	}
	lr := httptest.NewRecorder()
	s.handleCloudSessionTokens(lr, httptest.NewRequest(http.MethodGet, "/api/cloud-session/tokens", nil))
	var lv struct {
		Tokens []struct {
			Environment      string `json:"environment"`
			ExpiresInSeconds int64  `json:"expires_in_seconds"`
		} `json:"ship_tokens"`
	}
	if err := json.Unmarshal(lr.Body.Bytes(), &lv); err != nil || len(lv.Tokens) != 2 {
		t.Fatalf("list %s %v", lr.Body.String(), err)
	}
	for _, tv := range lv.Tokens {
		if tv.Environment == "" || tv.ExpiresInSeconds <= 0 || tv.ExpiresInSeconds > int64(shiptoken.DefaultLifetime/time.Second) {
			t.Fatalf("list row %+v", tv)
		}
	}
	rr := nodeShip(t, s, "Bearer "+secret, nodeShipEnvelope())
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"environment":"web env"`) {
		t.Fatalf("ship = %d %s", rr.Code, rr.Body.String())
	}
	var tagged int
	_ = database.QueryRow(`SELECT COUNT(*) FROM sessions WHERE reported_via_token = ?`, id).Scan(&tagged)
	if tagged == 0 {
		t.Fatal("the landed session is not tagged sandbox-reported")
	}
}

// TestNodeCloudSessionIngestSkipsLocalSession pins ledger CLOUDSESS-8 at the
// route: a batch naming a session this node captured itself writes nothing
// into it, and the receipt says why.
func TestNodeCloudSessionIngestSkipsLocalSession(t *testing.T) {
	s, database := newCloudSessionServer(t)
	if _, err := database.Exec(`INSERT INTO projects (id, root_path, created_at) VALUES (7, '/home/me/repo', '2026-10-31T09:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('local-1', 7, 'claude-code', '2026-10-31T09:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	secret, _ := mintNodeShipToken(t, s, `{"label":"web env"}`)
	env := nodeShipEnvelope()
	env.Actions = append(env.Actions, orgcontract.ActionRow{
		SessionID: "local-1", SourceEventID: "f1", Timestamp: "2026-10-31T10:00:01Z",
		Tool: "claude-code", ActionType: "run_command", Success: true,
	})
	rr := nodeShip(t, s, "Bearer "+secret, env)
	if rr.Code != http.StatusOK {
		t.Fatalf("ship = %d %s", rr.Code, rr.Body.String())
	}
	var rcpt shiptoken.Receipt
	_ = json.Unmarshal(rr.Body.Bytes(), &rcpt)
	if rcpt.SkippedSessions[shiptoken.SessionSkipLocal] != 1 || rcpt.DroppedRows["actions"] != 1 || rcpt.AcceptedRows != 2 {
		t.Fatalf("receipt %s", rr.Body.String())
	}
	var n int
	_ = database.QueryRow(`SELECT COUNT(*) FROM actions WHERE session_id = 'local-1'`).Scan(&n)
	var via sql.NullString
	_ = database.QueryRow(`SELECT reported_via_token FROM sessions WHERE id = 'local-1'`).Scan(&via)
	if n != 0 || via.String != "" {
		t.Fatalf("local session written: %d actions, tagged %q", n, via.String)
	}
}
