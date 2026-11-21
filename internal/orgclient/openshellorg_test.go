package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestOpenShellConstantsMatchTheCore pins the header names, domains and the
// mint body's JSON shape to the org-hosted core's (one owner of each).
func TestOpenShellConstantsMatchTheCore(t *testing.T) {
	if openShellHeaderProof != openshellorg.HeaderProof || openShellHeaderProofTS != openshellorg.HeaderProofTS {
		t.Error("proof header names differ from internal/openshellorg")
	}
	if OpenShellDomainMint != openshellorg.DomainMint || OpenShellDomainFetch != openshellorg.DomainFetch {
		t.Error("proof domains differ from internal/openshellorg")
	}
	a, b := reflect.TypeOf(OpenShellMintRequest{}), reflect.TypeOf(openshellorg.MintRequest{})
	if a.NumField() != b.NumField() {
		t.Fatalf("mint request fields %d, core %d", a.NumField(), b.NumField())
	}
	for i := 0; i < a.NumField(); i++ {
		if a.Field(i).Name != b.Field(i).Name || a.Field(i).Tag.Get("json") != b.Field(i).Tag.Get("json") {
			t.Errorf("field %d: %s %q, core %s %q", i, a.Field(i).Name, a.Field(i).Tag.Get("json"), b.Field(i).Name, b.Field(i).Tag.Get("json"))
		}
	}
	if openShellAgentPrefix != "/api/agent/sandbox/openshell" {
		t.Error("agent prefix")
	}
}

const (
	sentinelHandle   = "sbo-grant-handle-SENTINEL-0000"
	sentinelRunToken = "sbo-run-token-SENTINEL-0000"
)

// TestOpenShellRoutesSignWithTheAgentKey: every route carries the bearer and
// a proof the server verifies with the core's own NodeMessage over the exact
// body; a refusal comes back as its closed reason and names no secret.
func TestOpenShellRoutesSignWithTheAgentKey(t *testing.T) {
	SetOpenShellNodeMessage(openshellorg.NodeMessage)
	t.Cleanup(func() { SetOpenShellNodeMessage(nil) })
	s := newAgentStore(t)
	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	var pub ed25519.PublicKey
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/enroll" {
			var req orgcontract.EnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			k, _ := base64.RawURLEncoding.DecodeString(req.AgentPublicKey)
			pub = ed25519.PublicKey(k)
			writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{Bearer: "bearer-xyz", BearerExpiresAt: "2099-01-01T00:00:00Z", OrgID: "org-1", UserID: "m-1", UserEmail: "d@acme.example"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer bearer-xyz" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get(openshellorg.HeaderProofTS), 10, 64)
		sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get(openshellorg.HeaderProof))
		run, purpose, domain := "-", "", openshellorg.DomainMint
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			purpose = "login"
		case strings.HasSuffix(r.URL.Path, "/login/poll"):
			purpose = "poll"
		case strings.HasSuffix(r.URL.Path, "/grant"):
			purpose = "logout"
		case strings.HasSuffix(r.URL.Path, "/held"):
			purpose = "held"
		case strings.HasSuffix(r.URL.Path, "/token"):
			var m openshellorg.MintRequest
			_ = json.Unmarshal(body, &m)
			run, purpose = m.RunID, string(m.Purpose)
		case strings.Contains(r.URL.Path, "/collects/"):
			// The part is signed (OB-084): fetch:manifest with no part.
			part := r.URL.Query().Get("part")
			if part == "" {
				part = "manifest"
			}
			run, purpose, domain = strings.TrimPrefix(r.URL.Path, "/api/agent/sandbox/openshell/collects/"), "fetch:"+part, openshellorg.DomainFetch
		case strings.Contains(r.URL.Path, "/runs/"):
			parts := strings.Split(r.URL.Path, "/")
			run, purpose = parts[len(parts)-2], parts[len(parts)-1]
		}
		if !openshellorg.VerifyProof(pub, openshellorg.NodeMessage(domain, "org-1", run, purpose, ts, body), sig) || !openshellorg.Fresh(ts, time.Now()) {
			writeTestJSON(w, http.StatusForbidden, map[string]string{"error": "proof_invalid", "rule": "T0"})
			return
		}
		seen[r.Method+" "+r.URL.Path] = true
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			writeTestJSON(w, http.StatusOK, OpenShellLogin{DeviceCode: "dc-SENTINEL", UserCode: "ABCD-EFGH", VerificationURI: "https://org.example.com/sandbox/openshell/approve", ExpiresIn: 600, Interval: 5})
		case strings.HasSuffix(r.URL.Path, "/login/poll"):
			writeTestJSON(w, http.StatusOK, OpenShellGrant{GrantHandle: sentinelHandle, ExpiresAt: time.Now().Add(12 * time.Hour)})
		case strings.HasSuffix(r.URL.Path, "/token"):
			var m openshellorg.MintRequest
			_ = json.Unmarshal(body, &m)
			if m.GrantHandle != sentinelHandle || !m.LaptopRelay {
				writeTestJSON(w, http.StatusConflict, map[string]string{"error": "laptop_relay_not_opted_in", "rule": "T7h"})
				return
			}
			writeTestJSON(w, http.StatusOK, OpenShellMint{Token: sentinelRunToken, Purpose: string(m.Purpose), RunID: m.RunID, BoxRunID: m.RunID, BoxName: "obsabcdefghijklmnop", ExpiresAt: time.Now().Add(10 * time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/held"):
			writeTestJSON(w, http.StatusOK, map[string]any{"held": []OpenShellHeldBox{{RunID: "r9", State: "held", ResumeCount: 1}}})
		case strings.Contains(r.URL.Path, "/collects/"):
			serveCollect(w, r, collectServe{run: "r9", parts: `["diff","bundle"]`, bytes: map[string][]byte{"diff": []byte("diff"), "bundle": []byte("bundle")}})
		case strings.HasSuffix(r.URL.Path, "/ended"):
			writeTestJSON(w, http.StatusOK, OpenShellEndedAnswer{Outcome: "hold"})
		default:
			writeTestJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if _, _, err := c.Enroll(ctx, srv.URL, "tok_id.secret"); err != nil {
		t.Fatal(err)
	}
	l, err := c.OpenShellLoginStart(ctx, "")
	if err != nil || l.UserCode != "ABCD-EFGH" || strings.Contains(l.String(), "dc-SENTINEL") {
		t.Fatalf("login %v %v", l, err)
	}
	g, err := c.OpenShellLoginPoll(ctx, l.DeviceCode)
	if err != nil || g.GrantHandle != sentinelHandle || strings.Contains(g.String(), sentinelHandle) {
		t.Fatalf("poll %v %v", g, err)
	}
	m, err := c.OpenShellMintToken(ctx, OpenShellMintRequest{GrantHandle: g.GrantHandle, RunID: "r1", Purpose: "create", Tier: "proxy_only", Source: "clone-local", LaptopRelay: true})
	if err != nil || m.Token != sentinelRunToken || m.BoxName != "obsabcdefghijklmnop" {
		t.Fatalf("mint %v %v", m, err)
	}
	for _, s := range []string{m.String(), m.GoString()} {
		if strings.Contains(s, sentinelRunToken) {
			t.Errorf("the mint prints its token: %s", s)
		}
	}
	// A refused mint is its closed reason, with no secret in the error.
	_, err = c.OpenShellMintToken(ctx, OpenShellMintRequest{GrantHandle: g.GrantHandle, RunID: "r2", Purpose: "create"})
	var ref *OpenShellRefusal
	if !errors.As(err, &ref) || ref.Reason != "laptop_relay_not_opted_in" || ref.Rule != "T7h" || strings.Contains(err.Error(), sentinelHandle) {
		t.Errorf("refusal %v", err)
	}
	if a, err := c.OpenShellEndedReport(ctx, "r1", OpenShellEnded{Hold: true, BoxMinutes: 3}); err != nil || a.Outcome != "hold" {
		t.Errorf("ended %v %v", a, err)
	}
	if err := c.OpenShellHold(ctx, "r1"); err != nil {
		t.Errorf("hold %v", err)
	}
	if err := c.OpenShellDiscard(ctx, "r1"); err != nil {
		t.Errorf("discard %v", err)
	}
	if h, err := c.OpenShellHeld(ctx); err != nil || len(h) != 1 || h[0].RunID != "r9" {
		t.Errorf("held %v %v", h, err)
	}
	if col, err := c.OpenShellFetch(ctx, "r9"); err != nil || string(col.Diff) != "diff" {
		t.Errorf("fetch %v %v", col, err)
	}
	if err := c.OpenShellLogout(ctx, g.GrantHandle); err != nil {
		t.Errorf("logout %v", err)
	}
	if len(seen) != 9 { // the three fetch calls share one path
		t.Errorf("routes seen %v", seen)
	}
}

// TestOpenShellNotInBuildAndNotOffered: without the core's message helper
// nothing is sent; a bare 404 is "not offered".
func TestOpenShellNotInBuildAndNotOffered(t *testing.T) {
	SetOpenShellNodeMessage(nil)
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	if _, err := c.OpenShellHeld(context.Background()); !errors.Is(err, ErrOpenShellNotInBuild) {
		t.Errorf("not in build: %v", err)
	}
	SetOpenShellNodeMessage(openshellorg.NodeMessage)
	t.Cleanup(func() { SetOpenShellNodeMessage(nil) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/enroll" {
			writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{Bearer: "b", BearerExpiresAt: "2099-01-01T00:00:00Z", OrgID: "org-1", UserID: "m-1"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.OpenShellHeld(context.Background()); !errors.Is(err, ErrOpenShellNotOffered) {
		t.Errorf("404: %v", err)
	}
}

// g3CollectManifestJSON is lane G3's fetch manifest as its route serves it:
// openshellgw.Manifest, snake_case, with exactly these keys. G3's
// TestManifestShape owns the shape; the orchestrator adds a cross-package
// pin at merge. The format verbs are the run id, the two digests and the
// parts list.
const g3CollectManifestJSON = `{"run_id":"%s","diff_bytes":4,"bundle_bytes":6,"diff_sha256":"%s","bundle_sha256":"%s",` +
	`"collected_at":"2026-11-03T10:00:00Z","expires_at":"2026-12-03T10:00:00Z","reason":"hold_expired","parts":%s}`

// collectServe is what one fetch test's fake route answers: the manifest's
// run id and parts list, and each part's bytes.
type collectServe struct {
	run   string
	parts string
	bytes map[string][]byte
	// sizes replaces the manifest's byte counts when set (a real empty
	// collect says 0 and 0).
	sizes string
	// asked, when set, is the manifest's asked_run_id echo (lane FX6,
	// F-P8-3).
	asked string
}

// serveCollect answers the manifest, or a part with its digest header.
func serveCollect(w http.ResponseWriter, r *http.Request, c collectServe) {
	switch p := r.URL.Query().Get("part"); p {
	case "":
		w.Header().Set("Content-Type", "application/json")
		m := fmt.Sprintf(g3CollectManifestJSON, c.run, sha256Hex(c.bytes["diff"]), sha256Hex(c.bytes["bundle"]), c.parts)
		if c.sizes != "" {
			m = strings.Replace(m, `"diff_bytes":4,"bundle_bytes":6`, c.sizes, 1)
		}
		if c.asked != "" {
			m = strings.TrimSuffix(m, "}") + `,"asked_run_id":"` + c.asked + `"}`
		}
		_, _ = io.WriteString(w, m)
	default:
		w.Header().Set(openShellPartDigestHeader, sha256Hex(c.bytes[p]))
		_, _ = w.Write(c.bytes[p])
	}
}

// TestOpenShellFetchManifestAndParts (fix round 1, A2): the fetch reads the
// manifest, then each part, checks each part against both digests, and
// refuses a part whose bytes or header do not match.
func TestOpenShellFetchManifestAndParts(t *testing.T) {
	SetOpenShellNodeMessage(openshellorg.NodeMessage)
	t.Cleanup(func() { SetOpenShellNodeMessage(nil) })
	good := map[string][]byte{"diff": []byte("diff"), "bundle": []byte("bundle")}
	both := collectServe{run: "r9", parts: `["diff","bundle"]`, bytes: good}
	cases := []struct {
		name   string
		serve  collectServe
		tamper func(w http.ResponseWriter, r *http.Request) bool
		calls  string
		err    error
	}{
		{"manifest then both parts", both, nil, ",part=diff,part=bundle", nil},
		{"the diff only (no commits)", collectServe{run: "r9", parts: `["diff"]`, bytes: map[string][]byte{"diff": []byte("diff")}}, nil, ",part=diff", nil},
		{"another run's manifest", collectServe{run: "r8", parts: `["diff","bundle"]`, bytes: good}, nil, "", ErrOpenShellManifest},
		// A resumed run's own id: the org resolved it to the box's key and
		// says so (F-P8-3); a manifest that echoes another id is another box's.
		{"the box's key, echoing the asked id", collectServe{run: "rkey", parts: `["diff","bundle"]`, bytes: good, asked: "r9"}, nil, ",part=diff,part=bundle", nil},
		{"the box's key, echoing another id", collectServe{run: "rkey", parts: `["diff","bundle"]`, bytes: good, asked: "r7"}, nil, "", ErrOpenShellManifest},
		{"no diff listed", collectServe{run: "r9", parts: `["bundle"]`, bytes: good}, nil, "", ErrOpenShellManifest},
		{"no parts at all", collectServe{run: "r9", parts: `null`, bytes: good}, nil, "", ErrOpenShellManifest},
		{"an unknown part", collectServe{run: "r9", parts: `["diff","secrets"]`, bytes: good}, nil, "", ErrOpenShellManifest},
		{"a part listed twice", collectServe{run: "r9", parts: `["diff","diff"]`, bytes: good}, nil, "", ErrOpenShellManifest},
		{"nothing to save", collectServe{run: "r9", parts: `["diff"]`, bytes: map[string][]byte{"diff": {}}}, nil, "", ErrOpenShellManifest},
		{"a diff shorter than its byte count", collectServe{run: "r9", parts: `["diff","bundle"]`, bytes: map[string][]byte{"diff": []byte("dif"), "bundle": []byte("bundle")}}, nil, "", ErrOpenShellManifest},
		{"a bundle longer than its byte count", collectServe{run: "r9", parts: `["diff","bundle"]`, bytes: map[string][]byte{"diff": []byte("diff"), "bundle": []byte("bundle+")}}, nil, "", ErrOpenShellManifest},
		{"a real empty collect", collectServe{run: "r9", parts: `["diff"]`, bytes: map[string][]byte{"diff": {}}, sizes: `"diff_bytes":0,"bundle_bytes":0`}, nil, "", ErrOpenShellNothingCollected},
		{"a part whose bytes differ", both, func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Query().Get("part") != "bundle" {
				return false
			}
			w.Header().Set(openShellPartDigestHeader, sha256Hex(good["bundle"]))
			_, _ = w.Write([]byte("bundlX"))
			return true
		}, "", ErrOpenShellDigest},
		{"a part whose header differs", both, func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Query().Get("part") != "diff" {
				return false
			}
			w.Header().Set(openShellPartDigestHeader, sha256Hex([]byte("other")))
			_, _ = w.Write(good["diff"])
			return true
		}, "", ErrOpenShellDigest},
	}
	for _, tc := range cases {
		var queries []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/agent/enroll" {
				writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{Bearer: "b", BearerExpiresAt: "2099-01-01T00:00:00Z", OrgID: "org-1", UserID: "m-1"})
				return
			}
			queries = append(queries, r.URL.RawQuery)
			if tc.tamper != nil && tc.tamper(w, r) {
				return
			}
			serveCollect(w, r, tc.serve)
		}))
		c := newTestClient(t, newAgentStore(t), &memBearerStore{})
		if _, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret"); err != nil {
			t.Fatal(err)
		}
		col, err := c.OpenShellFetch(context.Background(), "r9")
		srv.Close()
		if tc.err == nil {
			if err != nil || string(col.Diff) != string(tc.serve.bytes["diff"]) || string(col.Bundle) != string(tc.serve.bytes["bundle"]) ||
				col.Manifest.RunID != tc.serve.run || col.Manifest.Reason != "hold_expired" || col.Manifest.DiffBytes != 4 {
				t.Errorf("%s: %+v %v", tc.name, col, err)
			}
			if strings.Join(queries, ",") != tc.calls {
				t.Errorf("%s: calls %v", tc.name, queries)
			}
			continue
		}
		if !errors.Is(err, tc.err) || col.Diff != nil || col.Bundle != nil {
			t.Errorf("%s: %v %+v", tc.name, err, col)
		}
		if !errors.Is(tc.err, ErrOpenShellNothingCollected) && errors.Is(err, ErrOpenShellNothingCollected) {
			t.Errorf("%s: read as nothing collected: %v", tc.name, err)
		}
	}
}
