package mcprelay_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentid"
	"github.com/marmutapp/superbased-observer/internal/dpop"
	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// memStore is an in-memory record.Store: it validates every row with
// record.Validate (Lane N-M's CHECK mirror), chains seqs, folds pending
// loss into a gap row inside Append, and can be made to fail.
type memStore struct {
	mu      sync.Mutex
	rows    []record.Record
	pending record.PendingLoss
	specs   map[string]record.LaunchSpec
	// failAppend / failSetLoss inject faults.
	failAppend  error
	failSetLoss error
	setLossN    int
}

func newMemStore() *memStore { return &memStore{specs: map[string]record.LaunchSpec{}} }

func (m *memStore) Append(_ context.Context, rec record.Record) (record.AppendResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAppend != nil {
		return record.AppendResult{}, m.failAppend
	}
	if err := rec.Validate(); err != nil {
		return record.AppendResult{}, err
	}
	var res record.AppendResult
	if m.pending.Count > 0 {
		g := record.Record{
			Kind: record.KindGap, TS: rec.TS, Family: record.DefaultFamily,
			GapFrom: record.Int(m.pending.FirstAt), GapTo: record.Int(m.pending.LastAt), LostCount: record.Int(m.pending.Count), GapReason: m.pending.Reason,
		}
		g.Seq = int64(len(m.rows) + 1)
		m.rows = append(m.rows, g)
		gg := g
		res.Gap = &gg
		m.pending = record.PendingLoss{}
	}
	if rec.Kind == record.KindCompletion {
		if rec.DecisionSeq == nil || *rec.DecisionSeq < 1 || *rec.DecisionSeq > int64(len(m.rows)) || m.rows[*rec.DecisionSeq-1].Kind != record.KindDecision {
			return record.AppendResult{}, fmt.Errorf("%w: completion without a decision parent", record.ErrInvalid)
		}
	}
	rec.Seq = int64(len(m.rows) + 1)
	m.rows = append(m.rows, rec)
	res.Record = rec
	return res, nil
}

func (m *memStore) Head(context.Context) (record.Head, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return record.Head{Seq: int64(len(m.rows))}, nil
}

func (m *memStore) Get(_ context.Context, seq int64) (record.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if seq < 1 || seq > int64(len(m.rows)) {
		return record.Record{}, record.ErrNotFound
	}
	return m.rows[seq-1], nil
}

func (m *memStore) ReadAfter(_ context.Context, after int64, limit int) ([]record.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []record.Record
	for _, r := range m.rows {
		if r.Seq > after {
			out = append(out, r)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *memStore) Verify(context.Context) (record.VerifyResult, error) {
	return record.VerifyResult{Records: len(m.rows)}, nil
}

func (m *memStore) PendingLoss(context.Context, string) (record.PendingLoss, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending, nil
}

func (m *memStore) SetPendingLoss(_ context.Context, _ string, p record.PendingLoss) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSetLoss != nil {
		return m.failSetLoss
	}
	m.setLossN++
	m.pending = p
	return nil
}

func (m *memStore) State(context.Context, string) (record.State, error) {
	return record.State{}, record.ErrNotFound
}
func (m *memStore) PutState(context.Context, record.State) error { return nil }

func specKey(c, p, k string) string { return c + "|" + p + "|" + k }

func (m *memStore) PutLaunchSpec(_ context.Context, s record.LaunchSpec, _ int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specs[specKey(s.Client, s.ConfigPath, s.EntryKey)] = s
	return nil
}

func (m *memStore) GetLaunchSpec(_ context.Context, c, p, k string) (record.LaunchSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.specs[specKey(c, p, k)]
	if !ok {
		return record.LaunchSpec{}, record.ErrNotFound
	}
	return s, nil
}

func (m *memStore) ListLaunchSpecs(context.Context) ([]record.LaunchSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []record.LaunchSpec
	for _, s := range m.specs {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) DeleteLaunchSpec(_ context.Context, c, p, k string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.specs, specKey(c, p, k))
	return nil
}

func (m *memStore) snapshot() []record.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]record.Record(nil), m.rows...)
}

func (m *memStore) kinds() []record.Kind {
	var out []record.Kind
	for _, r := range m.snapshot() {
		out = append(out, r.Kind)
	}
	return out
}

// fakeKeys is a KeyStore over one in-memory key. Loads are counted; there
// is structurally no Save.
type fakeKeys struct {
	key   orgclient.AgentAccessKey
	loads int
	err   error
}

func (k *fakeKeys) LoadAgentAccessKey() (orgclient.AgentAccessKey, error) {
	k.loads++
	if k.err != nil {
		return orgclient.AgentAccessKey{}, k.err
	}
	return k.key, nil
}

func newKey(t *testing.T, alg string) orgclient.AgentAccessKey {
	t.Helper()
	s, err := jose.GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	return orgclient.AgentAccessKey{Alg: alg, Signer: s}
}

func thumbprint(t *testing.T, k orgclient.AgentAccessKey) string {
	t.Helper()
	jwk, err := jose.PublicJWK(k.Signer.Public(), k.Alg, "")
	if err != nil {
		t.Fatal(err)
	}
	tp, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// fakeSTS is a token endpoint that verifies the token-endpoint DPoP proof
// shape, records the actor assertion's claims, and mints a random opaque
// token per exchange (the fake front accepts what the fake STS issued).
type fakeSTS struct {
	srv    *httptest.Server
	mu     sync.Mutex
	issued []string
	actors []map[string]any
	proofs []string
	// refuse, when set, is the OAuth error returned (status 400).
	refuse string
	status int
	// requireNonce demands a DPoP nonce once (use_dpop_nonce challenge).
	requireNonce bool
	nonce        string
	expiresIn    int64
	tokenType    string
}

func newFakeSTS(t *testing.T) *fakeSTS {
	t.Helper()
	s := &fakeSTS{expiresIn: 300, tokenType: "DPoP"}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *fakeSTS) endpoint() string { return s.srv.URL + "/oauth2/token" }

func (s *fakeSTS) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", 400)
		return
	}
	proof := r.Header.Get("DPoP")
	s.proofs = append(s.proofs, proof)
	w.Header().Set("Content-Type", "application/json")
	if s.refuse != "" {
		st := s.status
		if st == 0 {
			st = 400
		}
		w.WriteHeader(st)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": s.refuse})
		return
	}
	if r.PostForm.Get("grant_type") != agentid.GrantTypeTokenExchange || proof == "" || r.PostForm.Get("actor_token") == "" {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}
	j, err := jose.Parse(proof, 0)
	if err != nil || j.Header.Typ != dpop.Typ {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_dpop_proof"})
		return
	}
	var pc map[string]any
	_ = json.Unmarshal(j.Payload, &pc)
	if s.requireNonce {
		if n, _ := pc["nonce"].(string); s.nonce == "" || n != s.nonce {
			s.nonce = "nonce-" + randHex()
			w.Header().Set("DPoP-Nonce", s.nonce)
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "use_dpop_nonce"})
			return
		}
	}
	aj, err := jose.Parse(r.PostForm.Get("actor_token"), 0)
	if err != nil || aj.Header.Typ != agentid.TypActorAssertion {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	var ac map[string]any
	_ = json.Unmarshal(aj.Payload, &ac)
	s.actors = append(s.actors, ac)
	tok := "tok-" + randHex()
	s.issued = append(s.issued, tok)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": tok, "token_type": s.tokenType, "expires_in": s.expiresIn,
		"issued_token_type": agentid.TokenTypeAccessToken,
	})
}

func (s *fakeSTS) lastActor() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.actors) == 0 {
		return nil
	}
	return s.actors[len(s.actors)-1]
}

func (s *fakeSTS) issuedTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.issued...)
}

func (s *fakeSTS) knows(tok string) bool {
	for _, t := range s.issuedTokens() {
		if t == tok {
			return true
		}
	}
	return false
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// frontReq is one request the fake front saw.
type frontReq struct {
	Path   string
	Token  string
	Proof  string
	Corr   *dpop.Correlation
	Method string
	Body   []byte
	Header http.Header
}

// fakeFront is a programmable stand-in for the org front: it requires the
// DPoP scheme + a proof (parsed, its sbo_corr recorded), checks the token
// against the fake STS, and answers by tool name.
type fakeFront struct {
	srv  *httptest.Server
	sts  *fakeSTS
	mu   sync.Mutex
	reqs []frontReq
	// deny lists tool names answered with a -32003 error.
	deny map[string]bool
	// reject401 makes the next N requests answer 401 invalid_token.
	reject401 int
	// sse answers with an event stream.
	sse bool
}

func newFakeFront(t *testing.T, sts *fakeSTS) *fakeFront {
	t.Helper()
	f := &fakeFront{sts: sts, deny: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeFront) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	scheme, tok, err := dpop.ParseAuthorization(r.Header.Get("Authorization"))
	req := frontReq{Path: r.URL.Path, Token: tok, Proof: r.Header.Get("DPoP"), Body: body, Header: r.Header.Clone()}
	var m mcprelay.Message
	_ = json.Unmarshal(body, &m)
	req.Method = m.Method
	if p, perr := jose.Parse(req.Proof, 0); perr == nil {
		var c dpop.Claims
		_ = json.Unmarshal(p.Payload, &c)
		req.Corr = c.Corr
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	reject := f.reject401 > 0
	if reject {
		f.reject401--
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err != nil || scheme != dpop.SchemeDPoP || req.Proof == "" || !f.sts.knows(tok) || reject {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", error_description="bad"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(mcprelay.ErrorFrame(nil, mcprelay.CodeInvalidRequest, "unauthorized: invalid_token"))
		return
	}
	if !m.HasID() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m.Params, &p)
	var out []byte
	if f.deny[p.Name] {
		out = mcprelay.ErrorFrame(m.ID, mcprelay.CodeForbidden, "Unknown tool: "+p.Name)
	} else {
		res, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"ok": true, "tool": p.Name, "echo": json.RawMessage(body)}})
		out = res
	}
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", out)
		return
	}
	_, _ = w.Write(out)
}

func (f *fakeFront) requests() []frontReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]frontReq(nil), f.reqs...)
}

// newRelay wires a relay against the fake STS + front over a memStore.
func newRelay(t *testing.T, sts *fakeSTS, front *fakeFront, store record.Store, mut func(*mcprelay.Options)) (*mcprelay.Relay, *fakeKeys) {
	t.Helper()
	keys := &fakeKeys{key: newKey(t, jose.AlgEdDSA)}
	tc, err := mcprelay.NewTokenClient(mcprelay.TokenClientConfig{
		TokenEndpoint: sts.endpoint(), Keys: keys, HTTP: http.DefaultClient,
		SubjectToken: func(context.Context) (string, error) { return "enrol-bearer", nil },
		Actor:        mcprelay.ActorSpec{NodeID: "node_t", CredentialID: "cred_t", MemberID: "usr_t", MachineFP: "fp_t", CredGen: 1, Agent: "agent:claude-code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := mcprelay.Options{
		GatewayURL: "https://mcp-gw.example", FrontURL: front.srv.URL, Tokens: tc, HTTP: http.DefaultClient,
		Records: store, SidecarPath: t.TempDir() + "/" + mcprelay.SidecarName, CaptureLevel: "L2",
	}
	if mut != nil {
		mut(&o)
	}
	r, err := mcprelay.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r, keys
}

func rpc(id int, method string, params map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return b
}

func toolCall(id int, name string) []byte {
	return rpc(id, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"q": "x"}})
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var _ = strings.TrimSpace
