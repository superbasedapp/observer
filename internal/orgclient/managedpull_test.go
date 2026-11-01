package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// mpServer is a fake org answering one managed-pull rail with whatever the
// test scripts next.
type mpServer struct {
	mu      sync.Mutex
	srv     *httptest.Server
	handler http.HandlerFunc
	inm     []string
}

func newMPServer(t *testing.T) *mpServer {
	t.Helper()
	m := &mpServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>Sign in</title>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		h := m.handler
		m.inm = append(m.inm, r.Header.Get("If-None-Match"))
		m.mu.Unlock()
		h(w, r)
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mpServer) set(h http.HandlerFunc) {
	m.mu.Lock()
	m.handler = h
	m.mu.Unlock()
}

func serveDoc(doc orgcontract.ManagedPullDoc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == managedPullETag(doc.Version) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		writeTestJSON(w, http.StatusOK, doc)
	}
}

// managedPullFixture is an enrolled client whose enrolment pins orgPub.
func managedPullFixture(t *testing.T, srvURL string) (*Client, ed25519.PrivateKey, *time.Time) {
	t.Helper()
	orgPub, orgPriv, _ := ed25519.GenerateKey(rand.Reader)
	c, _, _ := enrolledPRClient(t, srvURL)
	seedEnrolmentKey(t, c, srvURL, orgPub)
	now := time.Unix(1_900_000_000, 0)
	c.SetManagedPullClock(func() time.Time { return now })
	return c, orgPriv, &now
}

func signFor(t *testing.T, priv ed25519.PrivateKey, rail, subject string, version, expires int64, body string) orgcontract.ManagedPullDoc {
	t.Helper()
	r, _ := orgcontract.LookupManagedPullRail(rail)
	doc, err := orgcontract.SignManagedPull(priv, r, "org-1", subject, version, expires, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

var managed = ManagedPullConsent{Managed: true, HoldsAuthority: true}

// TestFetchManagedPull_Rows walks every reply the ladder distinguishes
// against a real HTTP round trip, from a stored v2 document.
func TestFetchManagedPull_Rows(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	v2 := signFor(t, priv, "security", "scim-42", 2, exp, `{"enable":["security.deps"]}`)

	m.set(serveDoc(v2))
	out, err := c.FetchManagedPull(ctx, "security", managed)
	if err != nil || out.State != ManagedPullStateOK || out.Action != ManagedPullInstall || !out.InForce || out.Version != 2 {
		t.Fatalf("first 200: %+v %v", out, err)
	}
	// The conditional request rides the stored version.
	out, _ = c.FetchManagedPull(ctx, "security", managed)
	if out.State != ManagedPullStateOK || out.Action != ManagedPullKeep || m.inm[len(m.inm)-1] != managedPullETag(2) {
		t.Fatalf("304: %+v inm=%v", out, m.inm)
	}

	keepRows := []struct {
		name  string
		h     http.HandlerFunc
		state string
	}{
		{"404 never clears", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "not_supported"})
		}, ManagedPullStateNotSupported},
		{"302 to /login (R11)", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusFound)
		}, ManagedPullStateNotSupported},
		{"401", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}, ManagedPullStateAuthFailed},
		{"403", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		}, ManagedPullStateAuthFailed},
		{"409", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": "policy_channel_off"})
		}, ManagedPullStateChannelOff},
		{"503", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "x"})
		}, ManagedPullStateUnreachable},
		{"non-JSON 200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello"))
		}, ManagedPullStateNotSupported},
		{"unsigned 200", func(w http.ResponseWriter, _ *http.Request) {
			d := v2
			d.Version, d.Signature = 3, ""
			writeTestJSON(w, http.StatusOK, d)
		}, ManagedPullStateUnverified},
		{"unknown field 200", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, map[string]any{"schema": v2.Schema, "extra": 1})
		}, ManagedPullStateUnverified},
		{"another node's document", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, signFor(t, priv, "security", "someone-else", 3, exp, `{}`))
		}, ManagedPullStateUnverified},
		{"the sandbox rail's document", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, signFor(t, priv, "sandbox", "scim-42", 3, exp, `{}`))
		}, ManagedPullStateUnverified},
		{"expired on arrival", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, signFor(t, priv, "security", "scim-42", 3, now.Unix()-1, `{"a":1}`))
		}, ManagedPullStateExpiredOnArrival},
		{"rollback", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, signFor(t, priv, "security", "scim-42", 1, exp, `{"a":1}`))
		}, ManagedPullStateRollbackRefused},
		{"same version, other body", func(w http.ResponseWriter, _ *http.Request) {
			writeTestJSON(w, http.StatusOK, signFor(t, priv, "security", "scim-42", 2, exp, `{"a":2}`))
		}, ManagedPullStateSameVersionDifferentBody},
	}
	for _, row := range keepRows {
		m.set(row.h)
		out, err := c.FetchManagedPull(ctx, "security", managed)
		if err != nil || out.State != row.state || out.Version != 2 || !out.InForce {
			t.Errorf("%s: %+v %v, want state %s with v2 still in force", row.name, out, err, row.state)
		}
	}
	// A transport failure keeps it too.
	m.srv.Close()
	if out, err := c.FetchManagedPull(ctx, "security", managed); err != nil || out.State != ManagedPullStateUnreachable || !out.InForce {
		t.Fatalf("transport: %+v %v", out, err)
	}
}

// TestFetchManagedPull_ClearAndExpiry: only a signed empty body at a newer
// version clears; an expired stored body stops applying; a non-managed or
// authority-less node holds the body verified but inert; the stored document
// survives a restart (LoadPersistedManagedPull).
func TestFetchManagedPull_ClearAndExpiry(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	v1 := signFor(t, priv, "sandbox", "scim-42", 1, now.Unix()+60, `{"backends":["gvisor"]}`)
	m.set(serveDoc(v1))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", ManagedPullConsent{Managed: true}); out.InForce || out.Version != 1 {
		t.Fatalf("no authority must be inert: %+v", out)
	}
	if out, _ := c.FetchManagedPull(ctx, "sandbox", ManagedPullConsent{HoldsAuthority: true}); out.InForce {
		t.Fatalf("an individual node must be inert: %+v", out)
	}
	if out, _ := c.LoadPersistedManagedPull(ctx, "sandbox", managed); !out.InForce || out.State != ManagedPullStateUnreachable || string(out.Body) != `{"backends":["gvisor"]}` {
		t.Fatalf("persisted: %+v", out)
	}
	// Expiry: the stored body stops applying.
	later := now.Add(2 * time.Minute)
	c.SetManagedPullClock(func() time.Time { return later })
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.InForce || out.State != ManagedPullStateExpired {
		t.Fatalf("expired: %+v", out)
	}
	// A signed empty body at a newer version clears.
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 2, later.Unix()+60, `{}`)))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.State != ManagedPullStateCleared || out.InForce || out.Version != 0 {
		t.Fatalf("clear: %+v", out)
	}
	if out, _ := c.LoadPersistedManagedPull(ctx, "sandbox", managed); out.Version != 0 || out.InForce {
		t.Fatalf("cleared must stay cleared after a restart: %+v", out)
	}
	if _, err := c.FetchManagedPull(ctx, "nope", managed); err == nil {
		t.Fatal("an unknown rail must be refused")
	}
}

// TestDecideManagedPullExhaustive walks every combination of the ladder's
// inputs (the JSP-1 prototype's 2,304) and checks every rule holds.
func TestDecideManagedPullExhaustive(t *testing.T) {
	const now = int64(1000)
	replies := []ManagedPullReply{ManagedPullReply200, ManagedPullReply304, ManagedPullReply404, ManagedPullReplyNotSupported, ManagedPullReplyAuthFailed, ManagedPullReply409, ManagedPullReply5xx, ManagedPullReplyTransport}
	verdicts := []ManagedPullVerdict{ManagedPullVerified, ManagedPullVerifiedEmpty, ManagedPullUnverified}
	caches := []ManagedPullCacheFacts{{}, {Have: true, Version: 5, BodyHash: "a", ExpiresAt: now + 10, Floor: 5, FloorBodyHash: "a"}, {Have: true, Version: 5, BodyHash: "a", ExpiresAt: now - 10, Floor: 5, FloorBodyHash: "a"}}
	versions := []struct {
		v    int64
		hash string
	}{{4, "a"}, {5, "a"}, {5, "b"}, {6, "c"}}
	expiries := []int64{now + 100, now - 1}
	n := 0
	for _, r := range replies {
		for _, vd := range verdicts {
			for _, c := range caches {
				for _, v := range versions {
					for _, e := range expiries {
						for _, managedNode := range []bool{false, true} {
							for _, auth := range []bool{false, true} {
								n++
								in := ManagedPullInput{Reply: r, Verdict: vd, Version: v.v, BodyHash: v.hash, ExpiresAt: e, Now: now, Managed: managedNode, HoldsAuthority: auth}
								d := DecideManagedPull(in, c)
								after := ApplyManagedPull(d, in, c)
								name := fmt.Sprintf("%+v %+v -> %+v", in, c, d)
								changed := after != c
								if changed && r != ManagedPullReply200 {
									t.Fatalf("a non-200 changed the cache: %s", name)
								}
								if changed && vd == ManagedPullUnverified {
									t.Fatalf("an unverified body changed the cache: %s", name)
								}
								if c.Have && !after.Have && !(vd == ManagedPullVerifiedEmpty && v.v > c.Version) {
									t.Fatalf("cleared without a signed empty body at a newer version: %s", name)
								}
								if after.Have && c.Have && after.Version < c.Version {
									t.Fatalf("rollback: %s", name)
								}
								if after.floor() < c.floor() {
									t.Fatalf("the anti-rollback floor went down: %s", name)
								}
								want := after.Have && after.ExpiresAt > now && managedNode && auth
								if d.InForce != want {
									t.Fatalf("in-force rule: %s", name)
								}
								if d.State == "" {
									t.Fatalf("no state: %s", name)
								}
							}
						}
					}
				}
			}
		}
	}
	if n != 2304 {
		t.Fatalf("walked %d combinations, want 2304", n)
	}
}

// TestDecideManagedPullFloorSurvivesAClear is the two-step ladder test of
// audit SHR-KIT finding 2: step 1 installs v5 and a signed empty v6 clears
// it; step 2 replays the older, non-empty, unexpired v5, which the cleared
// floor refuses (before the fix the clear forgot v6 and v5 installed). A
// stored document that no longer verifies keeps its floor the same way, and
// a different body at the floor's own version is refused.
func TestDecideManagedPullFloorSurvivesAClear(t *testing.T) {
	const now = int64(1000)
	step := func(c ManagedPullCacheFacts, in ManagedPullInput) (ManagedPullDecision, ManagedPullCacheFacts) {
		in.Reply, in.Now, in.Managed, in.HoldsAuthority = ManagedPullReply200, now, true, true
		d := DecideManagedPull(in, c)
		return d, ApplyManagedPull(d, in, c)
	}
	v5 := ManagedPullInput{Verdict: ManagedPullVerified, Version: 5, BodyHash: "a", ExpiresAt: now + 3600}
	d, c := step(ManagedPullCacheFacts{}, v5)
	if d.Action != ManagedPullInstall || !d.InForce {
		t.Fatalf("install v5: %+v", d)
	}
	d, c = step(c, ManagedPullInput{Verdict: ManagedPullVerifiedEmpty, Version: 6, BodyHash: "e", ExpiresAt: now + 3600})
	if d.Action != ManagedPullClear || d.State != ManagedPullStateCleared || c.Have || c.Floor != 6 {
		t.Fatalf("clear at v6: %+v -> %+v", d, c)
	}
	d, after := step(c, v5)
	if d.Action != ManagedPullRefuse || d.State != ManagedPullStateRollbackRefused || d.InForce || after != c {
		t.Fatalf("a replayed v5 after the v6 clear must be refused: %+v -> %+v", d, after)
	}
	// A different body at the cleared version is refused too; the same
	// empty body again is a harmless re-clear.
	if d, _ := step(c, ManagedPullInput{Verdict: ManagedPullVerified, Version: 6, BodyHash: "b", ExpiresAt: now + 3600}); d.State != ManagedPullStateSameVersionDifferentBody {
		t.Fatalf("another body at the cleared version: %+v", d)
	}
	if d, again := step(c, ManagedPullInput{Verdict: ManagedPullVerifiedEmpty, Version: 6, BodyHash: "e", ExpiresAt: now + 3600}); d.InForce || again != c {
		t.Fatalf("the same empty body again: %+v -> %+v", d, again)
	}
	// A newer document installs over the tombstone.
	if d, _ := step(c, ManagedPullInput{Verdict: ManagedPullVerified, Version: 7, BodyHash: "c", ExpiresAt: now + 3600}); d.Action != ManagedPullInstall || !d.InForce {
		t.Fatalf("v7 over the tombstone: %+v", d)
	}
	// A stored v5 that no longer verifies (say, after a key rotation) holds
	// nothing in force but keeps its floor: v4 is refused, and v5's own body
	// re-signed installs again.
	unverified := ManagedPullCacheFacts{Floor: 5, FloorBodyHash: "a"}
	if d, _ := step(unverified, ManagedPullInput{Verdict: ManagedPullVerified, Version: 4, BodyHash: "z", ExpiresAt: now + 3600}); d.State != ManagedPullStateRollbackRefused {
		t.Fatalf("v4 under an unverifiable v5: %+v", d)
	}
	if d, _ := step(unverified, v5); d.Action != ManagedPullInstall || !d.InForce {
		t.Fatalf("v5 re-signed over an unverifiable v5: %+v", d)
	}
}

// TestFetchManagedPull_ReplayAfterClearIsRefused is the same two steps over
// a real HTTP round trip and the node's own table: v2 installs, a signed
// empty v3 clears and leaves a tombstone, a replayed v2 is refused and
// nothing is stored, and the tombstone survives a restart.
func TestFetchManagedPull_ReplayAfterClearIsRefused(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	v2 := signFor(t, priv, "security", "scim-42", 2, exp, `{"enable":["security.deps"]}`)
	m.set(serveDoc(v2))
	if out, err := c.FetchManagedPull(ctx, "security", managed); err != nil || out.Action != ManagedPullInstall || !out.InForce {
		t.Fatalf("install v2: %+v %v", out, err)
	}
	m.set(serveDoc(signFor(t, priv, "security", "scim-42", 3, exp, `{}`)))
	if out, err := c.FetchManagedPull(ctx, "security", managed); err != nil || out.State != ManagedPullStateCleared || out.InForce {
		t.Fatalf("clear at v3: %+v %v", out, err)
	}
	m.set(serveDoc(v2))
	out, err := c.FetchManagedPull(ctx, "security", managed)
	if err != nil || out.State != ManagedPullStateRollbackRefused || out.InForce || out.Version != 0 || len(out.Body) != 0 {
		t.Fatalf("a replayed v2 after the v3 clear must be refused: %+v %v", out, err)
	}
	if out, _ := c.LoadPersistedManagedPull(ctx, "security", managed); out.InForce || out.Version != 0 {
		t.Fatalf("after a restart nothing is in force: %+v", out)
	}
	m.set(serveDoc(v2))
	if out, _ := c.FetchManagedPull(ctx, "security", managed); out.State != ManagedPullStateRollbackRefused {
		t.Fatalf("the floor must survive a restart: %+v", out)
	}
}

// TestFetchManagedPullAdvertisesCapabilities (lane SHR-FOLLOWUPS,
// SBX-GOV-3): the sandbox rail's pull names sandbox.skip_repo_scan, so a
// newer server may serve that field; another rail names nothing. A newer
// node talking to an older server: that server ignores the header and
// serves the body it always did, which the node applies. Since lane
// LEFT-SHARED the security rail names its served fields too.
func TestFetchManagedPullAdvertisesCapabilities(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	var got []string
	record := func(doc orgcontract.ManagedPullDoc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.Header.Get(orgcontract.ManagedPullCapabilitiesHeader))
			writeTestJSON(w, http.StatusOK, doc)
		}
	}
	m.set(record(signFor(t, priv, "sandbox", "scim-42", 1, exp, `{"schema":"sbo-sandbox-managed-v1","node":{"extra_rw_binds":["/srv/cache"]}}`)))
	out, err := c.FetchManagedPull(ctx, "sandbox", managed)
	if err != nil || out.State != ManagedPullStateOK || !out.InForce {
		t.Fatalf("sandbox pull from an older server: %+v %v", out, err)
	}
	m.set(record(signFor(t, priv, "security", "scim-42", 1, exp, `{"enable":["security.deps"]}`)))
	if _, err := c.FetchManagedPull(ctx, "security", managed); err != nil {
		t.Fatal(err)
	}
	// The security rail names its served fields (lane LEFT-SHARED,
	// security_pullcaps.go); an older server ignores them the same way.
	if len(got) != 2 || got[0] != orgcontract.SandboxCapabilitySkipRepoScan+","+orgcontract.SandboxCapabilityE2BEndpoint+","+orgcontract.SandboxCapabilityInstallScripts+","+orgcontract.SandboxCapabilitySignInSeedForbid ||
		got[1] != strings.Join(managedPullCapabilities["security"], ",") || !strings.Contains(got[1], orgcontract.SecurityCapabilityBaselineApprovals) {
		t.Fatalf("capability headers sent: %q", got)
	}
}
