package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// signedManifest builds the envelope an org server would serve, using the
// SAME message builder the server's publish path uses
// (update.ManifestSigningMessage) — which is the point: one owner, two
// callers, no drift.
func signedManifest(t *testing.T, priv ed25519.PrivateKey, keyID string, m update.Manifest) update.Envelope {
	t.Helper()
	canonical, err := update.CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := update.HashBytes(canonical)
	return update.Envelope{
		ManifestB64:  base64.StdEncoding.EncodeToString(canonical),
		ManifestHash: hash,
		KeyID:        keyID,
		Signature: base64.StdEncoding.EncodeToString(
			ed25519.Sign(priv, update.ManifestSigningMessage(m.ManifestVersion, hash))),
	}
}

// testManifest is a valid publication for the CURRENT platform, so the
// artifact rule (9) selects a row rather than reporting no_artifact.
func testManifest(version string, manifestVersion int64) update.Manifest {
	goos, goarch := update.CurrentPlatform()
	return update.Manifest{
		Schema: update.SchemaV1, Channel: update.ChannelStable,
		ManifestVersion: manifestVersion, Version: version,
		ReleasedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:  time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Notes:      "A test publication.",
		Artifacts: []update.Artifact{{
			Kind: update.KindAgent, OS: goos, Arch: goarch,
			ArchiveType: update.DefaultArchiveTypeFor(goos),
			Filename:    "observer-" + version + "-test.tar.gz",
			SizeBytes:   1234, SHA256: strings.Repeat("a", 64),
			Member: update.BinaryName(goos), MemberSHA256: strings.Repeat("b", 64),
			AliasMembers:    []string{update.AliasName(goos)},
			UpstreamSigType: update.SigTypeEd25519, UpstreamSig: "c2ln",
		}},
	}
}

// enrol writes the singleton enrolment row so the fetch has a server URL.
func enrol(t *testing.T, s *store.Store, serverURL string) {
	t.Helper()
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-acme", OrgName: "Acme", OrgServerURL: serverURL,
		UserID: "scim-42", UserEmail: "dev@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
}

func TestFetchOrgUpdateManifestVerifiesAndCaches(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := base64.StdEncoding.EncodeToString(pub)

	var gotAuth, gotChannel string
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotAuth = r.Header.Get("Authorization")
		gotChannel = r.URL.Query().Get("channel")
		writeTestJSON(w, http.StatusOK, signedManifest(t, priv, keyID, testManifest("v1.33.0", 17)))
	}))
	defer srv.Close()

	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	c.agentVersion = "v1.32.0"

	changed, err := c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable)
	if err != nil {
		t.Fatalf("FetchOrgUpdateManifest: %v", err)
	}
	if !changed {
		t.Fatal("a first accepted manifest must report a change")
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("Authorization = %q — the manifest rail rides the ENROLMENT credential", gotAuth)
	}
	if gotChannel != "stable" {
		t.Fatalf("channel = %q, want stable", gotChannel)
	}
	st := c.UpdateStatus()
	if st.Version != "v1.33.0" || st.ManifestVersion != 17 || st.State != update.StateAvailable {
		t.Fatalf("status = %+v, want v1.33.0/17/available", st)
	}
	// Re-fetching the SAME ordinal is not a change: the replay rule short-
	// circuits it, which is what keeps a steady-state fleet quiet.
	changed, err = c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable)
	if err != nil || changed {
		t.Fatalf("re-fetch: changed=%v err=%v, want false/nil", changed, err)
	}
	if calls != 2 {
		t.Fatalf("server calls = %d, want 2", calls)
	}
}

// TestFetchRefusesAKeyThatDisagreesWithAnotherRailsPin is the "a node with a
// pinned key refuses a manifest signed by a different key" gate: one org has
// ONE distribution identity, and a manifest is not a chance to introduce a
// second one by TOFU on a long-enrolled node.
func TestFetchRefusesAKeyThatDisagreesWithAnotherRailsPin(t *testing.T) {
	impostorPub, impostorPriv, _ := ed25519.GenerateKey(nil)
	orgPub, _, _ := ed25519.GenerateKey(nil)
	impostorKeyID := base64.StdEncoding.EncodeToString(impostorPub)
	orgKeyID := base64.StdEncoding.EncodeToString(orgPub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, signedManifest(t, impostorPriv, impostorKeyID, testManifest("v1.33.0", 17)))
	}))
	defer srv.Close()

	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	// The ANNOUNCEMENT rail already pinned the org's real key months ago.
	if err := s.UpsertOrgAnnouncement(context.Background(), store.OrgAnnouncementRow{
		Version: 3, Body: "", BodyHash: "h", Signature: "sig",
		ServerPubkey: orgKeyID, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgAnnouncement: %v", err)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.agentVersion = "v1.32.0"

	if _, err := c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable); err == nil {
		t.Fatal("a manifest signed by a key the announcement rail did not pin must be REFUSED")
	} else if !strings.Contains(err.Error(), "key CHANGED") {
		t.Fatalf("err = %v, want the cross-rail key-change refusal", err)
	}
	if st := c.UpdateStatus(); st.State != update.StateIdle {
		t.Fatalf("state after a refusal = %q, want idle — a refused document changes nothing", st.State)
	}
}

// TestNotifyIsFailOpen pins §2.4: a document that cannot be decoded, whose
// hash does not match, or whose signature is wrong produces NO state change
// and nothing an operator must clear.
func TestNotifyIsFailOpen(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := base64.StdEncoding.EncodeToString(pub)

	cases := []struct {
		name string
		body func() any
	}{
		{"tampered manifest hash", func() any {
			env := signedManifest(t, priv, keyID, testManifest("v1.33.0", 17))
			env.ManifestHash = strings.Repeat("f", 64)
			return env
		}},
		{"tampered signature", func() any {
			env := signedManifest(t, priv, keyID, testManifest("v1.33.0", 17))
			env.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			return env
		}},
		{"unknown schema", func() any {
			m := testManifest("v1.33.0", 17)
			m.Schema = "sbo.update-manifest.v2"
			return signedManifest(t, priv, keyID, m)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeTestJSON(w, http.StatusOK, tc.body())
			}))
			defer srv.Close()
			s := newAgentStore(t)
			enrol(t, s, srv.URL)
			c := newTestClient(t, s, &memBearerStore{bearer: "b"})
			c.agentVersion = "v1.32.0"
			changed, err := c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable)
			if err != nil {
				t.Fatalf("notify must be FAIL-OPEN: got err %v", err)
			}
			if changed {
				t.Fatal("an ignored document must not report a change")
			}
			if st := c.UpdateStatus(); st.State != update.StateIdle {
				t.Fatalf("state = %q, want idle — no banner, no state change", st.State)
			}
		})
	}
}

// TestPreFeatureServerLeavesTheNodeInert is acceptance criterion 4's node
// half: a new agent against a server that has never heard of updates (404, or
// a response with no update_versions key) stays idle and makes no extra call.
func TestPreFeatureServerLeavesTheNodeInert(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.agentVersion = "v1.32.0"

	// A push acknowledgment with no update_versions key at all — the shape a
	// pre-feature server returns — must queue NOTHING.
	c.noteUpdateNudge([]byte(`{"accepted_rows":3,"deduped_rows":0,"next_cursor":10}`))
	c.FetchPendingUpdateManifests(context.Background())
	if calls != 0 {
		t.Fatalf("server calls = %d, want 0 — an un-nudged node must add NO request to the push cycle", calls)
	}
	if st := c.UpdateStatus(); st.State != update.StateIdle {
		t.Fatalf("state = %q, want idle", st.State)
	}

	changed, err := c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable)
	if err != nil || changed {
		t.Fatalf("a 404 must read as 'nothing published': changed=%v err=%v", changed, err)
	}
}

// TestNudgeOnlyFetchesWhenTheServerIsAhead is the zero-extra-egress property
// (acceptance 3) stated as a test: the nudge decides, and it decides against
// fetching in every case but a genuine advance.
func TestNudgeOnlyFetchesWhenTheServerIsAhead(t *testing.T) {
	c := newTestClient(t, newAgentStore(t), &memBearerStore{bearer: "b"})
	c.updates.lastAccepted = map[string]int64{"stable": 17}

	cases := []struct {
		name string
		ack  string
		want []update.Channel
	}{
		{"no update_versions key (pre-feature server)", `{"accepted_rows":1}`, nil},
		{"empty map", `{"update_versions":{}}`, nil},
		{"same ordinal", `{"update_versions":{"stable":17}}`, nil},
		{"older ordinal", `{"update_versions":{"stable":16}}`, nil},
		{"advanced", `{"update_versions":{"stable":18}}`, []update.Channel{update.ChannelStable}},
		{"a channel this node has never accepted", `{"update_versions":{"lts":1}}`, []update.Channel{update.ChannelLTS}},
		{"an unknown channel is ignored, not fetched", `{"update_versions":{"canary":99}}`, nil},
		{"unparseable body", `not json`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.updates.pending = nil
			c.noteUpdateNudge([]byte(tc.ack))
			got := c.takePendingUpdateChannels()
			if len(got) != len(tc.want) {
				t.Fatalf("pending = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("pending = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestBlockedPostureIsRecordedNotIgnored is the other half of §2.4: rules 6-9
// produce a posture the ADMIN needs to see, so unlike a rule 1-5 failure they
// are cached and reported as a change.
func TestBlockedPostureIsRecordedNotIgnored(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := base64.StdEncoding.EncodeToString(pub)
	m := testManifest("v1.33.0", 17)
	m.Artifacts[0].UpstreamSig = "" // the fail-closed interim (review H0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, signedManifest(t, priv, keyID, m))
	}))
	defer srv.Close()
	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.agentVersion = "v1.32.0"

	changed, err := c.FetchOrgUpdateManifest(context.Background(), update.ChannelStable)
	if err != nil {
		t.Fatalf("a blocked posture is a FACT, not an error: %v", err)
	}
	if !changed {
		t.Fatal("a posture change must be reported so the board can render it")
	}
	st := c.UpdateStatus()
	if st.State != update.StateBlocked || st.Reason != update.ReasonUnsignedArtifact {
		t.Fatalf("state/reason = %q/%q, want blocked/unsigned_artifact", st.State, st.Reason)
	}
}

// TestPushEnvelopeStaysByteIdenticalWithoutAPosture is acceptance criterion 4
// at the wire level, in BOTH directions:
//
//   - a node that reports no posture encodes exactly the bytes it encodes
//     today (the field is a pointer with omitempty), so a v1.7-shaped push is
//     still what the server receives; and
//   - a v1.7-SHAPED body — one that has never heard of the field — still
//     decodes into the new envelope type, which is what lets a v1.8 server
//     keep ingesting from older agents.
func TestPushEnvelopeStaysByteIdenticalWithoutAPosture(t *testing.T) {
	env := orgcontract.PushEnvelope{AgentVersion: "1.30.0", CursorFrom: 1, CursorTo: 2}
	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "update_posture") {
		t.Fatalf("an envelope with no posture named update_posture: %s", encoded)
	}
	var legacy orgcontract.PushEnvelope
	if err := json.Unmarshal([]byte(`{"agent_version":"1.7.26","cursor_from":1,"cursor_to":2,`+
		`"sessions":[],"actions":[],"api_turns":[],"token_usage":[]}`), &legacy); err != nil {
		t.Fatalf("a v1.7-shaped envelope must still decode: %v", err)
	}
	if legacy.UpdatePosture != nil {
		t.Fatal("a v1.7-shaped envelope must leave UpdatePosture nil, which the server reads as 'unknown'")
	}

	// And with a posture set, the field appears and round-trips.
	env.UpdatePosture = &orgcontract.UpdatePostureRow{Version: "v1.30.0", State: "idle"}
	encoded, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"update_posture"`) {
		t.Fatalf("a set posture did not reach the wire: %s", encoded)
	}
}

// --- review fix round 2 ------------------------------------------------------

// TestVerifiedManifestIsPersistedForNotifyOnlyNodes is H3.
//
// A BYO node (auto_apply off) is the DEFAULT shape of any fleet, and it never
// runs an apply — so before this the only writer of update_state was the apply
// path, and a notify-only node showed `idle` with no target on its own Health
// card, no banner, an idle row on the org board, and refused a daemon-less
// `observer update apply` with "this node holds no accepted manifest".
func TestVerifiedManifestIsPersistedForNotifyOnlyNodes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := base64.StdEncoding.EncodeToString(pub)
	man := testManifest("v9.9.9", 17)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, signedManifest(t, priv, keyID, man))
	}))
	defer srv.Close()

	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.agentVersion = "v1.32.0"
	ctx := context.Background()

	changed, err := c.FetchOrgUpdateManifest(ctx, update.ChannelStable)
	if err != nil || !changed {
		t.Fatalf("FetchOrgUpdateManifest = (%v, %v), want (true, nil)", changed, err)
	}

	row, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatalf("LoadUpdateState: %v", err)
	}
	if row.State != update.StateAvailable {
		t.Errorf("state = %q, want available - the banner and the card both gate on it", row.State)
	}
	if row.TargetVersion != "v9.9.9" {
		t.Errorf("target_version = %q, want v9.9.9", row.TargetVersion)
	}
	if row.LastManifestVersion != 17 {
		t.Errorf("last_manifest_version = %d, want 17", row.LastManifestVersion)
	}
	if strings.TrimSpace(row.ManifestJSON) == "" {
		t.Fatal("last_manifest_json is empty: a daemon-less `observer update apply` would refuse forever")
	}
	if strings.TrimSpace(row.LastManifestSeenAt) == "" {
		t.Error("last_manifest_seen_at is empty")
	}
	// The stored bytes are the SIGNED bytes, so a later apply runs the
	// document the signature covered.
	decoded, err := update.DecodeManifest([]byte(row.ManifestJSON))
	if err != nil {
		t.Fatalf("the stored manifest does not decode: %v", err)
	}
	if decoded.Version != "v9.9.9" || decoded.ManifestVersion != 17 {
		t.Errorf("stored manifest = %+v, want v9.9.9 / 17", decoded)
	}

	// A RESTART: a brand-new client over the same store still knows the
	// replay high-water mark, which is what migration 105's comment promised
	// and what rule 6 reads.
	fresh := newTestClient(t, s, &memBearerStore{bearer: "b"})
	fresh.agentVersion = "v1.32.0"
	_, lastAccepted, perr := fresh.updatePins(ctx, update.ChannelStable, keyID)
	if perr != nil {
		t.Fatalf("updatePins: %v", perr)
	}
	if lastAccepted != 17 {
		t.Errorf("last accepted after a restart = %d, want 17 - replay protection reset", lastAccepted)
	}
}

// TestBlockedPostureIsPersistedWithoutTheDocument: a rule 6-9 outcome IS a
// posture the board must show, but its bytes must never become something a
// later apply runs from.
func TestBlockedPostureIsPersistedWithoutTheDocument(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := base64.StdEncoding.EncodeToString(pub)
	man := testManifest("v9.9.9", 21)
	// No artifact for this platform: verify rule 9 -> blocked{no_artifact}.
	man.Artifacts[0].OS = "plan9"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, signedManifest(t, priv, keyID, man))
	}))
	defer srv.Close()

	s := newAgentStore(t)
	enrol(t, s, srv.URL)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	c.agentVersion = "v1.32.0"
	ctx := context.Background()
	if _, err := c.FetchOrgUpdateManifest(ctx, update.ChannelStable); err != nil {
		t.Fatalf("FetchOrgUpdateManifest: %v", err)
	}
	row, err := s.LoadUpdateState(ctx)
	if err != nil {
		t.Fatalf("LoadUpdateState: %v", err)
	}
	if row.State != update.StateBlocked {
		t.Errorf("state = %q, want blocked - the org board learns 'this fleet needs MDM' from here", row.State)
	}
	if strings.TrimSpace(row.ManifestJSON) != "" {
		t.Error("a rule 6-9 document was stored; it must never become the bytes a later apply runs from")
	}
}

// TestA426RefusalStillLetsTheNodeFetchAManifest is H2.
//
// Under min_agent_version_action = "refuse" the one mechanism that can lift a
// node over the floor was gated behind the push the floor refuses: the nudge
// was read only on the 200 path, so a binary-installed auto-apply node
// re-POSTed forever and never fetched a manifest.
func TestA426RefusalStillLetsTheNodeFetchAManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := base64.StdEncoding.EncodeToString(pub)
	man := testManifest("v9.9.9", 31)

	var manifestGETs int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/agent/update/manifest") {
			manifestGETs++
			writeTestJSON(w, http.StatusOK, signedManifest(t, priv, keyID, man))
			return
		}
		writeTestJSON(w, http.StatusUpgradeRequired, orgcontract.AgentTooOldBody{
			Error: "agent_too_old", Message: "too old", Reason: update.RefusalReasonAgentTooOld,
			MinVersion: "v1.33.0", YourVersion: "v1.30.0",
			// The server's own half of the fix: the same nudge an accepted
			// push carries.
			UpdateVersions: map[string]int64{"stable": 31},
		})
	}))
	defer srv.Close()

	s := newAgentStore(t)
	bs := &memBearerStore{}
	agentPub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, agentPub)
	seedActivity(t, s, 2)
	c := newTestClient(t, s, bs)
	c.agentVersion = "v1.30.0"
	ctx := context.Background()

	if _, perr := c.PushOnce(ctx); !errors.Is(perr, ErrAgentTooOld) {
		t.Fatalf("PushOnce error = %v, want ErrAgentTooOld", perr)
	}
	if manifestGETs != 0 {
		t.Fatalf("the push itself fetched a manifest (%d); the fetch belongs to the next step", manifestGETs)
	}
	// The very next thing PushLoop does on every cycle, refused or not.
	c.FetchPendingUpdateManifests(ctx)
	if manifestGETs != 1 {
		t.Fatalf("manifest GETs after a 426 = %d, want 1 - a refused node never learns about the release that fixes it", manifestGETs)
	}
	if st := c.UpdateStatus(); st.Version != "v9.9.9" {
		t.Errorf("update status after the refused push = %+v, want the published target", st)
	}
}

// TestA426WithNoNudgeStillArmsTheChannel: the node's half must work against a
// server too old to send update_versions on a 426.
func TestA426WithNoNudgeStillArmsTheChannel(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	ctx := context.Background()
	c.markUpdateChannelPendingAfterRefusal(ctx)
	got := c.takePendingUpdateChannels()
	if len(got) != 1 || got[0] != update.ChannelStable {
		t.Fatalf("pending channels = %v, want [stable]", got)
	}
}
