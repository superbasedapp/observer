package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termlease"
)

// --- a minimal LaunchManager driving the control-audit lifecycle ---

// leaseAuditManager is a minimal LaunchManager for the dashboard package (which
// cannot import cmd's launchManagerAdapter). AcquireWriterRemote consumes the
// single-use terminal-control capability through the REAL controller
// (rc.ConsumeTerminalControl — the §4.γ.2 capability leg: a wrong confirm
// consumes nothing, single-use burn), returning a live fake writer on success so
// the WS bridge emits real request/consume/denied control-audit events. The full
// §4.δ conjunction + a real termsession lease are exercised by the cmd-side
// matrix + lease-audit tests; here we isolate the dashboard control events.
type leaseAuditManager struct {
	caps             termlease.CapabilityConsumer
	handle           string
	sub              *fakeSubscription
	denyAfterConsume atomic.Bool
}

func (m *leaseAuditManager) Create(LaunchSpec) (string, error)           { return m.handle, nil }
func (m *leaseAuditManager) CreateFresh(FreshLaunchSpec) (string, error) { return m.handle, nil }
func (m *leaseAuditManager) CreateResume(ResumeLaunchSpec) (string, string, error) {
	return m.handle, "R", nil
}
func (m *leaseAuditManager) CreateSetup(SetupSpec) (string, error) { return m.handle, nil }
func (m *leaseAuditManager) CreateGUI(GUILaunchSpec) (GUILaunchResult, error) {
	return GUILaunchResult{}, ErrLaunchGUIUnsupported
}
func (m *leaseAuditManager) GUIRuns() []GUIRunInfo                        { return nil }
func (m *leaseAuditManager) Subscribe(string) (LaunchSubscription, error) { return m.sub, nil }

func (m *leaseAuditManager) SubscribeRemote(string) (LaunchSubscription, error) { return m.sub, nil }
func (m *leaseAuditManager) IsSetupSession(string) bool                         { return false }
func (m *leaseAuditManager) IsRemoteSensitiveSession(string) bool               { return false }
func (m *leaseAuditManager) Unsubscribe(LaunchSubscription)                     {}
func (m *leaseAuditManager) AcquireWriterLocal(string) (LaunchWriter, error) {
	return newFakeWriter(), nil
}

func (m *leaseAuditManager) AcquireWriterRemote(req RemoteWriterRequest) (LaunchWriter, error) {
	ok := m.caps.ConsumeTerminalControl(req.CapabilityToken, req.Confirm, req.DeviceSessionID, req.Handle)
	if !ok {
		return nil, NewControlDeniedError(ControlDenialAuth, false, ErrLaunchExecuteUnavailable)
	}
	if m.denyAfterConsume.Load() {
		return nil, NewControlDeniedError(ControlDenialHeldLocally, true, errors.New("takeover disabled"))
	}
	return newFakeWriter(), nil
}
func (m *leaseAuditManager) Close(string)                                   {}
func (m *leaseAuditManager) SessionForRun(string) (string, bool)            { return "", false }
func (m *leaseAuditManager) Snapshot() []LaunchInfo                         { return nil }
func (m *leaseAuditManager) RevokeAllRemoteWriters(string) int              { return 0 }
func (m *leaseAuditManager) RevokeRemoteWriterByHolder(string, string) bool { return false }

// controlAuditHarness assembles the dashboard Server + real remote controller +
// leaseAuditManager, with BOTH audit feed paths (the approval handler's direct
// store write AND the RemoteAudit sink) landing in ONE node-local store — the
// production posture (cmd's remoteAuditSink writes the sink records to the same
// remote_audit table). Tests read the merged, id-ordered rows back.
type controlAuditHarness struct {
	st     *store.Store
	s      *Server
	rc     *remoteController
	device string // raw device-session cookie value
	fp     string // device fingerprint (Sessions()[].Fingerprint)
	handle string
	lm     *leaseAuditManager
}

func newControlAuditHarness(t *testing.T) *controlAuditHarness {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	h := &controlAuditHarness{st: st, handle: "TERM-lifecycle-1"}
	rc, enc := newReadyRemoteController(t)
	h.rc = rc.(*remoteController)
	h.device = pairViaRoutes(t, rc, enc)
	h.fp = h.rc.Sessions()[0].Fingerprint

	sub := newFakeSubscription()
	t.Cleanup(func() { close(sub.release) })
	lm := &leaseAuditManager{caps: h.rc, handle: h.handle, sub: sub}
	h.lm = lm

	// The RemoteAudit sink persists to the SAME store as the approval handler —
	// exactly what cmd's remoteAuditSink does in production.
	audit := auditSinkToStore(st)

	s, err := New(Options{DB: database, Remote: rc, RemoteAudit: audit, LaunchManager: lm})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.s = s
	return h
}

// TestTerminalControlAuditCapabilityConsumedBeforePolicyDenial pins the honest
// refused-takeover lifecycle: a valid one-time capability is consumed upstream,
// then lease policy denies, so consume is recorded before a held_locally denial
// and replaying the same approval is a genuine auth rejection.
func TestTerminalControlAuditCapabilityConsumedBeforePolicyDenial(t *testing.T) {
	h := newControlAuditHarness(t)
	ts := remoteExposedWSServer(t, h.s)
	defer ts.Close()
	capTok, confirm := h.approve(t)
	h.lm.denyAfterConsume.Store(true)
	c := h.dialWS(t, ts)
	defer c.CloseNow()
	_ = c.Write(context.Background(), websocket.MessageText,
		[]byte(`{"t":"acquire-writer","cap":"`+capTok+`","confirm":"`+confirm+`"}`))
	if !waitForControl(t, context.Background(), c, "control_denied") {
		t.Fatal("expected policy control_denied after capability consume")
	}
	h.lm.denyAfterConsume.Store(false)
	_ = c.Write(context.Background(), websocket.MessageText,
		[]byte(`{"t":"acquire-writer","cap":"`+capTok+`","confirm":"`+confirm+`"}`))
	if !waitForControl(t, context.Background(), c, "control_denied") {
		t.Fatal("expected replayed consumed capability to be auth-denied")
	}

	rows := h.rows(t)
	kinds := make([]string, 0, len(rows))
	foundHeldDetail := false
	for _, row := range rows {
		kinds = append(kinds, row.Kind)
		if row.Kind == "terminal_control_denied" && row.Detail == string(ControlDenialHeldLocally) {
			foundHeldDetail = true
		}
	}
	want := []string{
		"terminal_control_local_approval",
		"terminal_control_request",
		"terminal_control_capability_consume",
		"terminal_control_denied",
		"terminal_control_request",
		"terminal_control_denied",
	}
	if !stringsContainInOrder(kinds, want) {
		t.Fatalf("consumed-refusal audit kinds\n got: %v\nwant subsequence: %v", kinds, want)
	}
	if !foundHeldDetail {
		t.Fatalf("audit did not record held_locally policy denial honestly: %+v", rows)
	}
	assertRowsNoCanary(t, rows, []string{capTok, confirm, h.device})
}

func auditSinkToStore(st *store.Store) func(RemoteAuditRecord) {
	return func(rec RemoteAuditRecord) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = st.InsertRemoteAudit(ctx, store.RemoteAuditEvent{
			Kind: rec.Kind, SessionID: rec.SessionID, Principal: rec.Principal,
			RemoteAddr: rec.RemoteAddr, Route: rec.Route, Decision: rec.Decision, Detail: rec.Detail,
		})
	}
}

// rows returns the persisted remote_audit rows in chronological (id) order.
func (h *controlAuditHarness) rows(t *testing.T) []store.RemoteAuditEvent {
	t.Helper()
	recent, err := h.st.RecentRemoteAudit(context.Background(), 500)
	if err != nil {
		t.Fatalf("RecentRemoteAudit: %v", err)
	}
	out := make([]store.RemoteAuditEvent, 0, len(recent))
	for i := len(recent) - 1; i >= 0; i-- { // newest-first → chronological
		out = append(out, recent[i])
	}
	return out
}

// pairViaRoutes drives the controller's /api/remote/pair route to obtain a raw
// device-session cookie.
func pairViaRoutes(t *testing.T, rc RemoteController, enc string) string {
	t.Helper()
	var pair http.HandlerFunc
	for _, rt := range rc.Routes() {
		if rt.Pattern == "/api/remote/pair" {
			pair = rt.Handler
		}
	}
	if pair == nil {
		t.Fatal("no pair route")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/remote/pair", strings.NewReader(`{"secret":"`+enc+`"}`))
	rec := httptest.NewRecorder()
	pair(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pair = %d: %s", rec.Code, rec.Body.String())
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == remoteSessionCookie {
			return ck.Value
		}
	}
	t.Fatal("pair returned no cookie")
	return ""
}

// approve drives the LOCAL loopback approve-execute handler and returns the
// minted capability + confirm (and emits the terminal_control_local_approval
// audit row into the store).
func (h *controlAuditHarness) approve(t *testing.T) (capTok, confirm string) {
	t.Helper()
	loopback := h.s.Handler()
	ck, ct := getConfirm(t, loopback)
	body, _ := json.Marshal(map[string]string{"device": h.fp, "handle": h.handle})
	rec := postConfirm(t, loopback, "/api/remote/approve-execute", string(body), ck, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve-execute = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Capability string `json:"capability"`
		Confirm    string `json:"confirm"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode approve: %v", err)
	}
	return resp.Capability, resp.Confirm
}

// dialWS opens a remote-exposed /ws/launch bridge carrying the device cookie.
func (h *controlAuditHarness) dialWS(t *testing.T, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	base := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, base+"/ws/launch/"+h.handle, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin": {ts.URL},
			"Cookie": {remoteSessionCookie + "=" + h.device},
		},
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return c
}

// TestTerminalControlAuditLifecycle drives the full approve → acquire → write
// sequence over the remote-exposed WS and asserts (plan §8.1): the typed control
// events appear in order with the handle + device-fingerprint correlation; the
// capability_claim/confirm legs are collapsed into request + consume (documented);
// no capability/confirm/raw-session-id/terminal byte appears in any row; and a
// failed authorize audits a coarse denial without consuming a capability.
func TestTerminalControlAuditLifecycle(t *testing.T) {
	h := newControlAuditHarness(t)
	ts := remoteExposedWSServer(t, h.s)
	defer ts.Close()

	// --- failed authorize FIRST (wrong confirm): a coarse denial is audited and
	// the capability is NOT consumed (a follow-up correct acquire still works).
	capTok, confirm := h.approve(t)
	cBad := h.dialWS(t, ts)
	_ = cBad.Write(context.Background(), websocket.MessageText,
		[]byte(`{"t":"acquire-writer","cap":"`+capTok+`","confirm":"wrong-`+confirm+`"}`))
	if !waitForControl(t, context.Background(), cBad, "control_denied") {
		t.Fatal("expected control_denied for a wrong-confirm acquire")
	}
	_ = cBad.Close(websocket.StatusNormalClosure, "done")

	// --- successful acquire with the SAME (unburned) capability + keystroke.
	c := h.dialWS(t, ts)
	_ = c.Write(context.Background(), websocket.MessageText,
		[]byte(`{"t":"acquire-writer","cap":"`+capTok+`","confirm":"`+confirm+`"}`))
	if !waitForControl(t, context.Background(), c, "control_granted") {
		t.Fatal("expected control_granted for the correct acquire (capability must have survived the denial)")
	}
	_ = c.Write(context.Background(), websocket.MessageBinary, []byte("ls -la\n"))
	time.Sleep(150 * time.Millisecond)
	_ = c.Close(websocket.StatusNormalClosure, "done")
	time.Sleep(150 * time.Millisecond)

	rows := h.rows(t)
	kinds := make([]string, 0, len(rows))
	for _, e := range rows {
		kinds = append(kinds, e.Kind)
	}
	// Order: approval, then the denied attempt (request+denied), then the
	// successful attempt (request+consume).
	want := []string{
		"terminal_control_local_approval",
		"terminal_control_request",
		"terminal_control_denied",
		"terminal_control_request",
		"terminal_control_capability_consume",
	}
	if !stringsContainInOrder(kinds, want) {
		t.Fatalf("control audit kinds\n got: %v\nwant subsequence: %v", kinds, want)
	}

	// Handle correlates on every terminal_* row; device fingerprint correlates on
	// the capability-lifecycle rows.
	for _, e := range rows {
		if !strings.HasPrefix(e.Kind, "terminal_") {
			continue
		}
		if e.Route != h.handle {
			t.Errorf("row kind=%s route=%q, want handle %q", e.Kind, e.Route, h.handle)
		}
		if e.SessionID != h.fp {
			t.Errorf("row kind=%s device=%q, want fingerprint %q", e.Kind, e.SessionID, h.fp)
		}
	}

	// Canary: no capability, confirm, or raw device id in ANY field of ANY row.
	assertRowsNoCanary(t, rows, []string{capTok, confirm, h.device})
}

// TestTerminalDeniedFrameCoalesced pins that a lease-less viewer flooding forged
// frames yields BOUNDED terminal_denied_frame rows carrying a coalesced count
// (never one row per frame), and the counts sum to the exact drop total (§8.1).
func TestTerminalDeniedFrameCoalesced(t *testing.T) {
	h := newControlAuditHarness(t)
	ts := remoteExposedWSServer(t, h.s)
	defer ts.Close()

	c := h.dialWS(t, ts)
	const flood = 400
	for i := 0; i < flood; i++ {
		_ = c.Write(context.Background(), websocket.MessageBinary, []byte("x"))
	}
	time.Sleep(300 * time.Millisecond)
	_ = c.Close(websocket.StatusNormalClosure, "done")
	time.Sleep(200 * time.Millisecond)

	var rowCount, sum int
	for _, e := range h.rows(t) {
		if e.Kind != "terminal_denied_frame" {
			continue
		}
		rowCount++
		if e.Route != h.handle || e.SessionID != h.fp {
			t.Errorf("denied-frame row miscorrelated: route=%q device=%q", e.Route, e.SessionID)
		}
		n := parseDropped(t, e.Detail)
		if n < 1 {
			t.Errorf("denied-frame row has non-positive count: %q", e.Detail)
		}
		sum += n
	}
	if rowCount == 0 {
		t.Fatal("expected at least one terminal_denied_frame row")
	}
	if rowCount >= flood {
		t.Fatalf("denied frames were NOT coalesced: %d rows for %d frames", rowCount, flood)
	}
	if rowCount > flood/deniedFrameBatch+3 {
		t.Fatalf("too many denied-frame rows (%d) for %d frames — coalescing is too weak", rowCount, flood)
	}
	if sum != flood {
		t.Fatalf("coalesced counts sum to %d, want exactly %d (no dropped frame uncounted)", sum, flood)
	}
}

// TestDeniedFrameCoalescerBounds is a deterministic unit test of the coalescer's
// bound + count-preservation property, independent of any websocket timing.
func TestDeniedFrameCoalescerBounds(t *testing.T) {
	for _, n := range []int{1, 2, 127, 128, 129, 1000} {
		var rowCount, sum int
		d := &deniedFrameCoalescer{emit: func(count int) { rowCount++; sum += count }}
		for i := 0; i < n; i++ {
			d.note()
		}
		d.flush()
		if sum != n {
			t.Errorf("n=%d: coalesced counts sum to %d, want %d", n, sum, n)
		}
		if rowCount > n/deniedFrameBatch+2 {
			t.Errorf("n=%d: %d rows exceeds bound", n, rowCount)
		}
		if n > 0 && rowCount == 0 {
			t.Errorf("n=%d: no rows emitted", n)
		}
	}
}

func stringsContainInOrder(have, want []string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && h == want[i] {
			i++
		}
	}
	return i == len(want)
}

func assertRowsNoCanary(t *testing.T, rows []store.RemoteAuditEvent, secrets []string) {
	t.Helper()
	for _, e := range rows {
		fields := []string{e.Kind, e.SessionID, e.Principal, e.RemoteAddr, e.Route, e.Decision, e.Detail}
		for _, f := range fields {
			for _, sec := range secrets {
				if sec != "" && strings.Contains(f, sec) {
					t.Errorf("audit row kind=%s leaked a secret/raw id in field %q", e.Kind, f)
				}
			}
		}
	}
}

func parseDropped(t *testing.T, detail string) int {
	t.Helper()
	const p = "dropped="
	if !strings.HasPrefix(detail, p) {
		t.Fatalf("denied-frame detail %q missing %q prefix", detail, p)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(detail, p))
	if err != nil {
		t.Fatalf("bad dropped count %q: %v", detail, err)
	}
	return n
}
