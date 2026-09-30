package mcprelay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

func TestRelayForwardsWithDPoPAndCorr(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	r, keys := newRelay(t, sts, front, store, nil)
	ctx := context.Background()
	c := mcprelay.Call{
		Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "gh_search"), Transport: localpdp.TransportLoopbackHTTP,
		Corr: mcprelay.Correlation{CodingSessionID: "sess_1", TurnRef: "t7", ActionRef: "a9"},
	}
	v := r.Decide(ctx, c)
	if !v.Forward || v.CallID == "" || v.Attestation != "configured" {
		t.Fatalf("verdict %+v", v)
	}
	rp, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	r.Complete(ctx, v, rp.Outcome(), rp.Body, "")
	if rp.Status != 200 || rp.Outcome() != "ok" {
		t.Fatalf("reply %d %s", rp.Status, rp.Body)
	}
	reqs := front.requests()
	if len(reqs) != 1 {
		t.Fatalf("front saw %d requests", len(reqs))
	}
	fr := reqs[0]
	if fr.Path != "/mcp/gh" || !bytes.Equal(fr.Body, c.Raw) {
		t.Fatalf("path %q body %s", fr.Path, fr.Body)
	}
	if !sts.knows(fr.Token) {
		t.Fatal("front did not receive the STS-issued token")
	}
	if fr.Corr == nil || fr.Corr.CallID != v.CallID || fr.Corr.CodingSessionID != "sess_1" || fr.Corr.TurnRef != "t7" || fr.Corr.ActionRef != "a9" {
		t.Fatalf("sbo_corr %+v", fr.Corr)
	}
	// The proof key IS the agent-access key (cnf.jkt) and the proof carries ath.
	pj, err := jose.Parse(fr.Proof, 0)
	mustNoErr(t, err)
	tp, _ := pj.Header.JWK.Thumbprint()
	if tp != thumbprint(t, keys.key) {
		t.Fatal("proof signed by a key other than the agent-access key")
	}
	var pc map[string]any
	_ = json.Unmarshal(pj.Payload, &pc)
	if pc["ath"] == "" || pc["htm"] != "POST" || !strings.HasSuffix(pc["htu"].(string), "/mcp/gh") {
		t.Fatalf("proof claims %v", pc)
	}
	// The actor assertion carried the effective attestation + agent.
	act := sts.lastActor()
	if act["sbo_client_attestation"] != "configured" || act["sbo_agent"] != "agent:claude-code" || act["sub"] != "cred_t" {
		t.Fatalf("actor %v", act)
	}
	// Records: decision BEFORE forward, completion AFTER, both valid rows.
	rows := store.snapshot()
	if len(rows) != 2 || rows[0].Kind != record.KindDecision || rows[1].Kind != record.KindCompletion {
		t.Fatalf("rows %v", store.kinds())
	}
	d, cpl := rows[0], rows[1]
	if d.CallID != v.CallID || d.Decision != record.DecisionAllow || d.EventKind != record.EventCall || d.Tool != "gh_search" || d.VServer != "gh" ||
		d.CorrConfidence != record.CorrExact || d.CodingSessionID != "sess_1" || d.CaptureLevel != record.CaptureL2 || d.ArgsFull == "" || d.ArgsScrubStatus != record.ScrubStructured {
		t.Fatalf("decision row %+v", d)
	}
	if *cpl.DecisionSeq != d.Seq || cpl.CallID != v.CallID || cpl.ResultStatus != "ok" || cpl.ResultFull == "" || *cpl.ResultSizeBytes != int64(len(rp.Body)) {
		t.Fatalf("completion row %+v", cpl)
	}
}

func TestRelayL0RecordsCarryNoPayloadOrPlainNames(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	r, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.CaptureLevel = "L0" })
	ctx := context.Background()
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "gh_search"), Transport: localpdp.TransportLoopbackHTTP}
	v := r.Decide(ctx, c)
	rp, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	r.Complete(ctx, v, rp.Outcome(), rp.Body, "")
	rows := store.snapshot()
	if rows[0].ArgsFull != "" || rows[0].Tool != "" || rows[0].Server != "" || rows[1].ResultFull != "" || *rows[1].ResultSizeBytes == 0 {
		t.Fatalf("L0 rows leak content: %+v %+v", rows[0], rows[1])
	}
}

func TestRelayTokenCachedThenRotateAndRetryOnceOn401(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	r, _ := newRelay(t, sts, front, store, nil)
	ctx := context.Background()
	call := func(id int) *mcprelay.HTTPReply {
		c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(id, "gh_search"), Transport: localpdp.TransportLoopbackHTTP}
		v := r.Decide(ctx, c)
		rp, err := r.ForwardHTTP(ctx, c, v)
		mustNoErr(t, err)
		return rp
	}
	call(1)
	call(2)
	if n := len(sts.issuedTokens()); n != 1 {
		t.Fatalf("expected one cached exchange for two calls, got %d", n)
	}
	// The front refuses the (still cached) token once: exactly one
	// re-exchange and one retry.
	front.reject401 = 1
	rp := call(3)
	if rp.Status != 200 {
		t.Fatalf("retry after 401 failed: %d %s", rp.Status, rp.Body)
	}
	if n := len(sts.issuedTokens()); n != 2 {
		t.Fatalf("expected a second exchange after 401, got %d", n)
	}
	reqs := front.requests()
	if len(reqs) != 4 || reqs[2].Token == reqs[3].Token {
		t.Fatalf("expected retry with a fresh token: %d requests", len(reqs))
	}
	// A persistent 401 is NOT retried more than once (no loop).
	front.reject401 = 5
	rp = call(4)
	if rp.Status != 401 || rp.Outcome() != "denied" {
		t.Fatalf("second 401 must be final: %d", rp.Status)
	}
	if n := len(front.requests()); n != 6 {
		t.Fatalf("expected exactly 2 attempts for the final 401, saw %d total", n)
	}
}

func TestRelayFrontDenyIsRelayedAndRecorded(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	front.deny["rm_rf"] = true
	store := newMemStore()
	r, _ := newRelay(t, sts, front, store, nil)
	ctx := context.Background()
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(9, "rm_rf"), Transport: localpdp.TransportLoopbackHTTP}
	v := r.Decide(ctx, c)
	rp, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	r.Complete(ctx, v, rp.Outcome(), rp.Body, "")
	frames := rp.Frames(v.Msg.ID)
	if len(frames) != 1 {
		t.Fatalf("frames %d", len(frames))
	}
	m, _ := mcprelay.ParseMessage(frames[0])
	if m.Error == nil || m.Error.Code != mcprelay.CodeForbidden || string(m.ID) != "9" {
		t.Fatalf("deny frame %s", frames[0])
	}
	if rows := store.snapshot(); rows[1].ResultStatus != "error" || rows[1].ErrorFull == "" {
		t.Fatalf("completion %+v", rows[1])
	}
}

func TestRelaySSEReplyBecomesFrames(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	front.sse = true
	r, _ := newRelay(t, sts, front, newMemStore(), nil)
	ctx := context.Background()
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(3, "x"), Transport: localpdp.TransportLoopbackHTTP}
	v := r.Decide(ctx, c)
	rp, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	frames := rp.Frames(v.Msg.ID)
	if len(frames) != 1 {
		t.Fatalf("frames %d from %s", len(frames), rp.Body)
	}
	m, err := mcprelay.ParseMessage(frames[0])
	if err != nil || m.Result == nil {
		t.Fatalf("frame %s", frames[0])
	}
}

func TestRelayRefusesBatchParseAndNoTokenClient(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	r, _ := newRelay(t, sts, front, newMemStore(), nil)
	ctx := context.Background()
	for _, raw := range []string{`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, `not json`} {
		v := r.Decide(ctx, mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: []byte(raw)})
		if v.Forward || len(v.Refuse) == 0 {
			t.Fatalf("%q accepted", raw)
		}
	}
	r2, _ := newRelay(t, sts, front, newMemStore(), func(o *mcprelay.Options) { o.Tokens = nil })
	v := r2.Decide(ctx, mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "x")})
	if v.Forward {
		t.Fatal("remote call forwarded without a token client")
	}
}

// ---------------------------------------------------------------- records

func sidecarExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	t.Fatal(err)
	return false
}

func TestAsyncAppendFailureCommitsSidecarBeforeForward(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	sidecar := filepath.Join(t.TempDir(), mcprelay.SidecarName)
	r, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	ctx := context.Background()
	store.failAppend = errors.New("disk full")
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "a"), Transport: localpdp.TransportLoopbackHTTP}
	v := r.Decide(ctx, c)
	if !v.Forward {
		t.Fatalf("async mode must fail OPEN once the sidecar is durable: %s", v.Refuse)
	}
	if !sidecarExists(t, sidecar) {
		t.Fatal("sidecar not written before forward")
	}
	fi, _ := os.Stat(sidecar)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("sidecar perm %o", fi.Mode().Perm())
	}
	var sc mcprelay.LossSidecar
	raw, _ := os.ReadFile(sidecar)
	_ = json.Unmarshal(raw, &sc)
	if sc.Count != 1 || len(sc.AttemptedCallIDs) != 1 || sc.AttemptedCallIDs[0] != v.CallID || !strings.Contains(sc.Reason, "disk full") {
		t.Fatalf("sidecar %+v", sc)
	}
	rp, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	r.Complete(ctx, v, rp.Outcome(), rp.Body, "") // no parent row: absorbed by the loss
	if len(store.snapshot()) != 0 {
		t.Fatal("nothing should have been appended")
	}
	// A second failure accumulates.
	v2 := r.Decide(ctx, c)
	if !v2.Forward || r.PendingLoss().Count != 2 {
		t.Fatalf("loss %+v", r.PendingLoss())
	}
	// The store recovers: the NEXT append hands the loss over, the store
	// folds a gap row FIRST, then the decision; the sidecar is gone.
	store.failAppend = nil
	v3 := r.Decide(ctx, c)
	if !v3.Forward {
		t.Fatal(string(v3.Refuse))
	}
	kinds := store.kinds()
	if len(kinds) != 2 || kinds[0] != record.KindGap || kinds[1] != record.KindDecision {
		t.Fatalf("kinds %v", kinds)
	}
	if g := store.snapshot()[0]; *g.LostCount != 2 || !strings.Contains(g.GapReason, "disk full") {
		t.Fatalf("gap %+v", g)
	}
	if sidecarExists(t, sidecar) || r.PendingLoss().Count != 0 {
		t.Fatal("sidecar/pending loss not cleared after the fold")
	}
}

func TestStrictModeBlocksOnAppendFailure(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	sidecar := filepath.Join(t.TempDir(), mcprelay.SidecarName)
	r, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar; o.AuditMode = mcprelay.AuditStrict })
	store.failAppend = errors.New("locked")
	v := r.Decide(context.Background(), mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "a")})
	if v.Forward {
		t.Fatal("strict mode forwarded on an append failure")
	}
	m, _ := mcprelay.ParseMessage(v.Refuse)
	if m.Error == nil || m.Error.Code != mcprelay.CodeUnavailable || string(m.ID) != "1" {
		t.Fatalf("refusal %s", v.Refuse)
	}
	if sidecarExists(t, sidecar) {
		t.Fatal("strict mode must not write the loss sidecar")
	}
	if len(front.requests()) != 0 {
		t.Fatal("front reached")
	}
}

func TestSidecarUnwritableBlocks(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	// A sidecar path under a non-existent directory cannot be written.
	bad := filepath.Join(t.TempDir(), "missing", "sub", mcprelay.SidecarName)
	r, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = bad })
	store.failAppend = errors.New("db gone")
	v := r.Decide(context.Background(), mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "a")})
	if v.Forward {
		t.Fatal("both DB and sidecar unwritable must BLOCK")
	}
	// No sidecar configured at all: same, blocks.
	r2, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = "" })
	if v := r2.Decide(context.Background(), mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(2, "a")}); v.Forward {
		t.Fatal("no sidecar configured must BLOCK on append failure")
	}
}

// TestCrashBoundariesRecoverFromSidecar simulates a crash at each boundary
// by rebuilding the relay over the same store + sidecar.
func TestCrashBoundariesRecoverFromSidecar(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	store := newMemStore()
	sidecar := filepath.Join(t.TempDir(), mcprelay.SidecarName)
	ctx := context.Background()
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "a")}

	// Boundary 1: after the DB failure + sidecar commit, before forward:
	// the sidecar holds the loss; the store was never told (SetPendingLoss
	// failed too - the DB was down).
	store.failAppend, store.failSetLoss = errors.New("down"), errors.New("down")
	r, _ := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	if v := r.Decide(ctx, c); !v.Forward {
		t.Fatal("expected fail-open")
	}
	if store.setLossN != 0 {
		t.Fatal("store must not have accepted the loss while down")
	}
	// crash -> restart with the store healthy: the startup handoff gives
	// the loss to the store BEFORE serving, the next append folds a gap.
	store.failAppend, store.failSetLoss = nil, nil
	r, _ = newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	if p, _ := store.PendingLoss(ctx, record.DefaultFamily); p.Count != 1 {
		t.Fatalf("startup handoff did not reach the store: %+v", p)
	}
	if v := r.Decide(ctx, c); !v.Forward {
		t.Fatal(string(v.Refuse))
	}
	if k := store.kinds(); len(k) != 2 || k[0] != record.KindGap {
		t.Fatalf("kinds %v", k)
	}
	if sidecarExists(t, sidecar) {
		t.Fatal("sidecar should be removed after the fold")
	}

	// Boundary 2: the store accepted the loss (SetPendingLoss ok) but the
	// process crashed before any successful append; the sidecar and the
	// store agree (same count) -> no double count.
	store.failAppend = errors.New("down again")
	r, _ = newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	_ = r.Decide(ctx, c)
	if p, _ := store.PendingLoss(ctx, record.DefaultFamily); p.Count != 1 {
		t.Fatalf("store pending %+v", p)
	}
	store.failAppend = nil
	r, _ = newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	_ = r.Decide(ctx, c)
	rows := store.snapshot()
	last := rows[len(rows)-2]
	if last.Kind != record.KindGap || *last.LostCount != 1 {
		t.Fatalf("second fold should account exactly one loss: %+v", last)
	}

	// Boundary 3: corrupt sidecar -> counted as one loss of unknown extent.
	_ = os.WriteFile(sidecar, []byte("{garbage"), 0o600)
	r, _ = newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = sidecar })
	if r.PendingLoss().Count != 1 || !strings.Contains(r.PendingLoss().Reason, "unreadable") {
		t.Fatalf("corrupt sidecar %+v", r.PendingLoss())
	}
}

func TestAccessTokenNeverTouchesDisk(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	home := t.TempDir()
	store := newMemStore()
	r, keys := newRelay(t, sts, front, store, func(o *mcprelay.Options) { o.SidecarPath = filepath.Join(home, mcprelay.SidecarName) })
	ctx := context.Background()
	store.failAppend = errors.New("force a sidecar write")
	c := mcprelay.Call{Target: mcprelay.Target{VServer: "gh"}, Raw: toolCall(1, "a")}
	v := r.Decide(ctx, c)
	_, err := r.ForwardHTTP(ctx, c, v)
	mustNoErr(t, err)
	tok := sts.issuedTokens()[0]
	// The KeyStore has no Save (structural: the interface exposes Load
	// only) and was read exactly once per exchange.
	if keys.loads != 1 {
		t.Fatalf("key loads %d", keys.loads)
	}
	// Nothing under the relay's directory (sidecar included) holds the token.
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(tok)) {
			t.Fatalf("access token found on disk at %s", p)
		}
		return nil
	})
}

func TestLoopbackHTTPHandler(t *testing.T) {
	sts := newFakeSTS(t)
	front := newFakeFront(t, sts)
	front.deny["rm"] = true
	store := newMemStore()
	r, _ := newRelay(t, sts, front, store, nil)
	srv := httptest.NewServer(r.ServeLoopbackHTTP())
	defer srv.Close()
	post := func(body []byte, hdr map[string]string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp/gh", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		mustNoErr(t, err)
		b, _ := readAll(resp)
		return resp, b
	}
	resp, b := post(toolCall(1, "ok"), map[string]string{mcprelay.HeaderCodingSession: "sess_L"})
	if resp.StatusCode != 200 || !bytes.Contains(b, []byte(`"ok":true`)) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if fr := front.requests()[0]; fr.Corr == nil || fr.Corr.CodingSessionID != "sess_L" {
		t.Fatalf("corr header not carried: %+v", fr.Corr)
	}
	if act := sts.lastActor(); act["sbo_client_attestation"] != "configured" {
		t.Fatalf("loopback must be configured: %v", act)
	}
	resp, b = post(toolCall(2, "rm"), nil)
	if resp.StatusCode != 200 || !bytes.Contains(b, []byte(`-32003`)) {
		t.Fatalf("deny %d %s", resp.StatusCode, b)
	}
	resp, _ = post([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), nil)
	if resp.StatusCode != 202 {
		t.Fatalf("notification %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp/gh", nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 405 {
		t.Fatalf("GET %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if rows := store.snapshot(); len(rows) != 6 {
		t.Fatalf("expected 3 decisions + 3 completions, got %v", store.kinds())
	}
}

func readAll(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp.Body)
	return buf.Bytes(), err
}
