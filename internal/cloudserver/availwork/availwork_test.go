package availwork

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

const orgA = "ab0e3298-277a-4098-99d8-d62d320776ad"

// memStore is an in-memory IssueStore and DeliveryStore.
type memStore struct {
	inputs     []store.AvailabilityInputRow
	docs       []pc.AvailabilityDocument
	issuedBy   []string
	floor      int64
	pending    *store.AvailabilityIssueRequest
	finished   []store.AvailabilityIssueRequest
	deliveries map[string]store.AvailabilityDelivery
	storeErr   error
}

func (m *memStore) PendingAvailabilityIssue(context.Context) (store.AvailabilityIssueRequest, error) {
	if m.pending == nil {
		return store.AvailabilityIssueRequest{}, store.ErrNotFound
	}
	return *m.pending, nil
}

func (m *memStore) AvailabilityInputsForIssue(context.Context) ([]store.AvailabilityInputRow, error) {
	return m.inputs, m.storeErr
}

func (m *memStore) LatestAvailabilityDocument(context.Context) (pc.AvailabilityDocument, error) {
	if len(m.docs) == 0 {
		return pc.AvailabilityDocument{}, store.ErrNotFound
	}
	return m.docs[len(m.docs)-1], nil
}

func (m *memStore) DocumentVersionFloor(context.Context, pc.DocumentKind, string) (int64, error) {
	return m.floor, nil
}

func (m *memStore) IssueAvailabilityDocument(_ context.Context, id string, doc pc.AvailabilityDocument, by string, _ time.Time) error {
	last := m.floor
	if len(m.docs) > 0 {
		last = max(last, m.docs[len(m.docs)-1].Version)
	}
	if err := pc.CheckDocumentVersion(last, doc.Version); err != nil {
		return err
	}
	if m.pending == nil || m.pending.RequestID != id {
		return store.ErrIssueNotPending
	}
	m.docs = append(m.docs, doc)
	m.issuedBy = append(m.issuedBy, by)
	r := *m.pending
	r.State, r.ResultVersion = store.IssueStateIssued, doc.Version
	m.finished = append(m.finished, r)
	m.pending = nil
	return nil
}

func (m *memStore) FinishAvailabilityIssue(_ context.Context, id, state, class string, _ time.Time) error {
	if m.pending == nil || m.pending.RequestID != id {
		return store.ErrIssueNotPending
	}
	r := *m.pending
	r.State, r.ErrorClass = state, class
	m.finished = append(m.finished, r)
	m.pending = nil
	return nil
}

func (m *memStore) AvailabilityDeliveries(context.Context) ([]store.AvailabilityDelivery, error) {
	out := []store.AvailabilityDelivery{}
	for _, d := range m.deliveries {
		out = append(out, d)
	}
	return out, nil
}

func (m *memStore) RecordAvailabilityDelivery(_ context.Context, d store.AvailabilityDelivery) error {
	if m.deliveries == nil {
		m.deliveries = map[string]store.AvailabilityDelivery{}
	}
	if old, ok := m.deliveries[d.HostID]; ok {
		d.Version = max(d.Version, old.Version)
	}
	m.deliveries[d.HostID] = d
	return nil
}

func (m *memStore) last() store.AvailabilityIssueRequest { return m.finished[len(m.finished)-1] }

var now = time.Date(2026, 11, 23, 13, 0, 0, 0, time.UTC)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// keySigner signs like the document signer, refusing a version it already
// signed (or a lower one).
type keySigner struct {
	priv  ed25519.PrivateKey
	last  int64
	err   error
	calls int
}

func (k *keySigner) SignAvailability(_ context.Context, version int64, body []byte) ([]byte, string, error) {
	k.calls++
	if k.err != nil {
		return nil, "", k.err
	}
	if err := pc.CheckDocumentVersion(k.last, version); err != nil {
		return nil, "", err
	}
	if err := checkBodyLikeSigner(body); err != nil {
		return nil, "", err
	}
	sig, kid, err := pc.SignDocument(k.priv, pc.KindAvailability, pc.AvailabilityScope, version, body)
	if err == nil {
		k.last = version
	}
	return sig, kid, err
}

// checkBodyLikeSigner is signerd's availability body check.
func checkBodyLikeSigner(body []byte) error {
	_, err := availcompose.DecodeBody(body)
	return err
}

func pub(priv ed25519.PrivateKey) pc.KeySet {
	return pc.KeySet{pc.NewDocumentKey(priv.Public().(ed25519.PublicKey))}
}

func inputRows() []store.AvailabilityInputRow {
	return []store.AvailabilityInputRow{
		{Section: "components", Key: "org.security", Value: json.RawMessage(`{"reach":"named","orgs":["` + orgA + `"]}`), Reason: "offer to A", Author: "staff:s1"},
	}
}

func request(rows []store.AvailabilityInputRow, base int64) *store.AvailabilityIssueRequest {
	return &store.AvailabilityIssueRequest{
		RequestID: "11111111-1111-4111-8111-111111111111", RequestedBy: "staff:s1", Reason: "ship it",
		InputsDigest: availcompose.Digest(InputsFromRows(rows)), BaseVersion: base, State: store.IssueStatePending,
	}
}

func newIssuer(t *testing.T, m *memStore, s Signer, keys pc.KeySet) *Issuer {
	t.Helper()
	i, err := NewIssuer(IssuerConfig{Store: m, Signer: s, Keys: keys, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestIssueOnceIssues(t *testing.T) {
	t.Parallel()
	priv := newKey(t)
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	i := newIssuer(t, m, &keySigner{priv: priv}, pub(priv))
	out, err := i.IssueOnce(context.Background())
	if err != nil || out != OutcomeIssued {
		t.Fatalf("IssueOnce = %s, %v", out, err)
	}
	doc := m.docs[0]
	if doc.Version != now.Unix() {
		t.Errorf("version = %d, want the current Unix second %d", doc.Version, now.Unix())
	}
	if m.issuedBy[0] != "staff:s1" || m.last().State != store.IssueStateIssued || m.last().ResultVersion != doc.Version {
		t.Errorf("issued_by %q, request %+v", m.issuedBy[0], m.last())
	}
	if err := Verify(doc, pub(priv), 0); err != nil {
		t.Fatalf("the stored envelope does not verify: %v", err)
	}
	b, _ := availcompose.DecodeBody(doc.Body)
	if !availcompose.Offered(&b, "org.security", orgA) {
		t.Error("the issued envelope does not offer org.security to org A")
	}
	if out, _ := i.IssueOnce(context.Background()); out != OutcomeIdle {
		t.Errorf("second pass = %s, want idle", out)
	}
}

// TestIssueStaleness: one case per staleness rule, then the invalid inputs.
func TestIssueStaleness(t *testing.T) {
	t.Parallel()
	priv := newKey(t)
	issued := func() *memStore {
		m := &memStore{inputs: inputRows()}
		m.pending = request(m.inputs, 0)
		if out, err := newIssuer(t, m, &keySigner{priv: priv}, pub(priv)).IssueOnce(context.Background()); out != OutcomeIssued {
			t.Fatalf("setup: %s %v", out, err)
		}
		return m
	}
	cases := []struct {
		name  string
		setup func() *memStore
		out   Outcome
		state string
		class string
	}{
		{"inputs changed after the preview", func() *memStore {
			m := &memStore{inputs: inputRows()}
			m.pending = request(m.inputs, 0)
			m.inputs = append(m.inputs, store.AvailabilityInputRow{Section: "components", Key: "org.digest", Value: json.RawMessage(`{"reach":"off"}`), Reason: "r", Author: "staff:s2"})
			return m
		}, OutcomeStale, store.IssueStateStale, ClassInputsChanged},
		{"another envelope issued since", func() *memStore {
			m := issued()
			m.pending = request(m.inputs, 0) // previewed against "none issued"
			return m
		}, OutcomeStale, store.IssueStateStale, ClassVersionMoved},
		{"nothing to issue", func() *memStore {
			m := issued()
			m.pending = request(m.inputs, m.docs[0].Version)
			return m
		}, OutcomeStale, store.IssueStateStale, ClassNothingToDo},
		{"an input that no longer composes", func() *memStore {
			m := &memStore{inputs: []store.AvailabilityInputRow{{Section: "components", Key: "org.security", Value: json.RawMessage(`{"reach":"bogus"}`), Reason: "r", Author: "staff:s1"}}}
			m.pending = request(m.inputs, 0)
			return m
		}, OutcomeFailed, store.IssueStateFailed, ClassInvalidInputs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := c.setup()
			docs := len(m.docs)
			out, err := newIssuer(t, m, &keySigner{priv: priv, last: 1 << 40}, pub(priv)).IssueOnce(context.Background())
			if err != nil || out != c.out {
				t.Fatalf("IssueOnce = %s, %v; want %s", out, err, c.out)
			}
			if got := m.last(); got.State != c.state || got.ErrorClass != c.class {
				t.Fatalf("request = %s/%s, want %s/%s", got.State, got.ErrorClass, c.state, c.class)
			}
			if len(m.docs) != docs {
				t.Fatal("an envelope was stored for a refused request")
			}
		})
	}
}

func TestIssueBumpsPastTheSignersRecordAndTheFloor(t *testing.T) {
	t.Parallel()
	priv := newKey(t)
	m := &memStore{inputs: inputRows(), floor: now.Unix() + 10}
	m.pending = request(m.inputs, 0)
	s := &keySigner{priv: priv, last: now.Unix() + 12} // signed past the floor, never stored
	if out, err := newIssuer(t, m, s, pub(priv)).IssueOnce(context.Background()); out != OutcomeIssued || err != nil {
		t.Fatalf("IssueOnce = %s, %v", out, err)
	}
	if got := m.docs[0].Version; got != now.Unix()+13 {
		t.Errorf("version = %d, want %d (floor+1 bumped past the signer's record)", got, now.Unix()+13)
	}
}

func TestIssueSignerDownRetriesThenFails(t *testing.T) {
	t.Parallel()
	priv := newKey(t)
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	i := newIssuer(t, m, &keySigner{priv: priv, err: errors.New("dial unix: no such file")}, pub(priv))
	for n := 1; n < DefaultMaxFailures; n++ {
		if out, err := i.IssueOnce(context.Background()); out != OutcomeRetry || err == nil {
			t.Fatalf("pass %d = %s, %v; want retry with the error", n, out, err)
		}
		if m.pending == nil {
			t.Fatalf("pass %d finished the request", n)
		}
	}
	if out, _ := i.IssueOnce(context.Background()); out != OutcomeFailed || m.last().ErrorClass != ClassSign {
		t.Fatalf("last pass = %s, request %+v; want failed/sign", out, m.last())
	}
}

// TestIssueForgetsARequestCancelledElsewhere: a request staff cancel while
// the signer is down leaves no failure count behind once nothing is pending.
func TestIssueForgetsARequestCancelledElsewhere(t *testing.T) {
	t.Parallel()
	priv := newKey(t)
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	i := newIssuer(t, m, &keySigner{priv: priv, err: errors.New("dial unix: no such file")}, pub(priv))
	if out, _ := i.IssueOnce(context.Background()); out != OutcomeRetry || len(i.failures) != 1 {
		t.Fatalf("first pass = %s, failures %v", out, i.failures)
	}
	m.pending = nil // cancelled by staff (store.CancelAvailabilityIssue)
	if out, err := i.IssueOnce(context.Background()); out != OutcomeIdle || err != nil || len(i.failures) != 0 {
		t.Fatalf("idle pass = %s, %v, failures %v; want idle and none left", out, err, i.failures)
	}
}

func TestIssueRefusesAnEnvelopeHostsWouldNotVerify(t *testing.T) {
	t.Parallel()
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	signing, pinned := newKey(t), newKey(t) // the signer's key is not the pinned one
	out, err := newIssuer(t, m, &keySigner{priv: signing}, pub(pinned)).IssueOnce(context.Background())
	if out != OutcomeFailed || err == nil || m.last().ErrorClass != ClassVerify || len(m.docs) != 0 {
		t.Fatalf("IssueOnce = %s, %v, request %+v, docs %d", out, err, m.last(), len(m.docs))
	}
}

func TestNewIssuerNeedsItsSeams(t *testing.T) {
	t.Parallel()
	if _, err := NewIssuer(IssuerConfig{Store: &memStore{}, Signer: &keySigner{}}); err == nil {
		t.Fatal("NewIssuer accepted no keys")
	}
}

// TestSendTable: one case per send rule row.
func TestSendTable(t *testing.T) {
	t.Parallel()
	wait, confirm := time.Hour, 6*time.Hour
	recent, old := now.Add(-time.Minute), now.Add(-confirm)
	cases := []struct {
		name string
		d    *store.AvailabilityDelivery
		want string
		send bool
	}{
		{"never sent", nil, "never-sent", true},
		{"current", &store.AvailabilityDelivery{Version: 10, AttemptedVersion: 10, State: store.DeliveryDelivered, UpdatedAt: recent}, "current", false},
		{"newer on the host", &store.AvailabilityDelivery{Version: 12, AttemptedVersion: 10, State: store.DeliveryDelivered, UpdatedAt: recent}, "current", false},
		{"current, confirmation at the window", &store.AvailabilityDelivery{Version: 10, AttemptedVersion: 10, State: store.DeliveryDelivered, UpdatedAt: old}, "reconfirm", true},
		{"newer on the host, confirmation old", &store.AvailabilityDelivery{Version: 12, AttemptedVersion: 10, State: store.DeliveryDelivered, UpdatedAt: old.Add(-time.Hour)}, "reconfirm", true},
		{"refused this version recently", &store.AvailabilityDelivery{Version: 5, AttemptedVersion: 10, State: store.DeliveryRefused, UpdatedAt: now.Add(-time.Minute)}, "refused-recently", false},
		{"refused a re-send recently", &store.AvailabilityDelivery{Version: 10, AttemptedVersion: 10, State: store.DeliveryRefused, UpdatedAt: recent}, "refused-recently", false},
		{"refused this version long ago", &store.AvailabilityDelivery{Version: 5, AttemptedVersion: 10, State: store.DeliveryRefused, UpdatedAt: now.Add(-2 * time.Hour)}, "behind", true},
		{"refused an older version", &store.AvailabilityDelivery{Version: 5, AttemptedVersion: 9, State: store.DeliveryRefused, UpdatedAt: now}, "behind", true},
		{"retrying", &store.AvailabilityDelivery{Version: 5, AttemptedVersion: 10, State: store.DeliveryRetry, UpdatedAt: now}, "behind", true},
		// A re-send that failed in transit: the host's answer is not known,
		// so it is not current even though the row's version is.
		{"re-send retrying", &store.AvailabilityDelivery{Version: 10, AttemptedVersion: 10, State: store.DeliveryRetry, UpdatedAt: recent}, "behind", true},
	}
	for _, c := range cases {
		r := sendDecision(sendFacts{d: c.d, latest: 10, now: now, wait: wait, confirm: confirm})
		if r.name != c.want || r.send != c.send {
			t.Errorf("%s: rule %s send %v, want %s %v", c.name, r.name, r.send, c.want, c.send)
		}
	}
}

// fakeHosts answers availability pushes per host.
type fakeHosts struct {
	answer map[string]func(r hostapi.Request) hostapi.Answer
	sent   map[string]int
}

func (f *fakeHosts) Send(_ context.Context, host string, r hostapi.Request) hostapi.Answer {
	if f.sent == nil {
		f.sent = map[string]int{}
	}
	f.sent[host]++
	return f.answer[host](r)
}

func applied(r hostapi.Request) hostapi.Answer {
	var req pc.SetAvailabilityRequest
	_ = json.Unmarshal(r.Body, &req)
	b, _ := json.Marshal(pc.SetAvailabilityResponse{Version: req.Document.Version, Applied: true})
	return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: b}
}

func refusedInvalid(hostapi.Request) hostapi.Answer {
	b, _ := json.Marshal(pc.ErrorResponse{Code: pc.CodeInvalid, Field: "document"})
	return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: b}
}

func dialFails(hostapi.Request) hostapi.Answer {
	return hostapi.Answer{Kind: hostapi.AnswerTransport, Reason: "dial"}
}

func TestDeliverOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	priv := newKey(t)
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	if out, err := newIssuer(t, m, &keySigner{priv: priv}, pub(priv)).IssueOnce(ctx); out != OutcomeIssued {
		t.Fatal(out, err)
	}
	v := m.docs[0].Version
	hosts := &fakeHosts{answer: map[string]func(hostapi.Request) hostapi.Answer{"app-0": applied, "app-1": refusedInvalid, "app-2": dialFails}}
	clock := now
	d, err := NewDeliverer(DelivererConfig{Store: m, Transport: hosts, Hosts: func() []string { return []string{"app-0", "app-1", "app-2"} }, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.DeliverOnce(ctx)
	if err != nil || st.Sent != 3 || st.Delivered != 1 || st.Refused != 1 || st.Retry != 1 {
		t.Fatalf("first pass = %+v, %v", st, err)
	}
	want := map[string]struct {
		state   string
		version int64
		class   string
	}{
		"app-0": {store.DeliveryDelivered, v, ""},
		"app-1": {store.DeliveryRefused, 0, "refused:invalid"},
		"app-2": {store.DeliveryRetry, 0, "transport:dial"},
	}
	for h, w := range want {
		got := m.deliveries[h]
		if got.State != w.state || got.Version != w.version || got.ErrorClass != w.class || got.AttemptedVersion != v || got.Attempts != 1 {
			t.Errorf("%s = %+v, want %+v", h, got, w)
		}
	}
	// Second pass: app-0 is current, app-1 is held (refused this version
	// a minute ago), app-2 is retried.
	clock = now.Add(time.Minute)
	st, _ = d.DeliverOnce(ctx)
	if st.Current != 1 || st.Held != 1 || st.Sent != 1 || m.deliveries["app-2"].Attempts != 2 {
		t.Fatalf("second pass = %+v, app-2 %+v", st, m.deliveries["app-2"])
	}
	// The host comes back; a newer envelope reaches app-1 at once.
	hosts.answer["app-1"], hosts.answer["app-2"] = applied, applied
	m.inputs = append(m.inputs, store.AvailabilityInputRow{Section: "components", Key: "org.digest", Value: json.RawMessage(`{"reach":"off"}`), Reason: "r", Author: "staff:s1"})
	m.pending = request(m.inputs, v)
	if out, err := newIssuer(t, m, &keySigner{priv: priv, last: v}, pub(priv)).IssueOnce(ctx); out != OutcomeIssued {
		t.Fatal(out, err)
	}
	v2 := m.docs[1].Version
	st, err = d.DeliverOnce(ctx)
	if err != nil || st.Delivered != 3 {
		t.Fatalf("third pass = %+v, %v", st, err)
	}
	for _, h := range []string{"app-0", "app-1", "app-2"} {
		if got := m.deliveries[h]; got.Version != v2 || got.State != store.DeliveryDelivered || got.Attempts != 1 {
			t.Errorf("%s = %+v, want v%d delivered after 1 attempt", h, got, v2)
		}
	}
}

// restorableHost is a host that holds one envelope version and can be
// restored from an old backup (its version falls back without the cloud
// being told).
type restorableHost struct {
	holds   int64
	applied int
}

func (h *restorableHost) answer(r hostapi.Request) hostapi.Answer {
	var req pc.SetAvailabilityRequest
	_ = json.Unmarshal(r.Body, &req)
	resp := pc.SetAvailabilityResponse{Version: h.holds}
	if req.Document.Version > h.holds {
		h.holds, h.applied = req.Document.Version, h.applied+1
		resp = pc.SetAvailabilityResponse{Version: h.holds, Applied: true}
	}
	b, _ := json.Marshal(resp)
	return hostapi.Answer{Kind: hostapi.AnswerVerified, Body: b}
}

// TestDeliverOnceReconfirmsAfterTheWindow: a host marked current is checked
// again once its confirmation is older than the window. A host restored from
// an old backup gets the newest envelope again; a host that still holds it
// answers Applied=false, nothing changes on it, and the row's time moves on.
func TestDeliverOnceReconfirmsAfterTheWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	priv := newKey(t)
	m := &memStore{inputs: inputRows()}
	m.pending = request(m.inputs, 0)
	if out, err := newIssuer(t, m, &keySigner{priv: priv}, pub(priv)).IssueOnce(ctx); out != OutcomeIssued {
		t.Fatal(out, err)
	}
	v := m.docs[0].Version
	host := &restorableHost{}
	hosts := &fakeHosts{answer: map[string]func(hostapi.Request) hostapi.Answer{"app-0": host.answer}}
	clock := now
	d, err := NewDeliverer(DelivererConfig{Store: m, Transport: hosts, Hosts: func() []string { return []string{"app-0"} }, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := d.DeliverOnce(ctx); err != nil || st.Delivered != 1 || host.holds != v {
		t.Fatalf("first pass = %+v, %v, host holds v%d", st, err, host.holds)
	}

	// The host is restored from a backup taken before v: it holds nothing.
	host.holds = 0
	clock = now.Add(time.Hour)
	if st, _ := d.DeliverOnce(ctx); st.Current != 1 || st.Sent != 0 {
		t.Fatalf("inside the window = %+v, want current, nothing sent", st)
	}
	window := DefaultConfirmAfter
	clock = now.Add(window + time.Minute)
	st, err := d.DeliverOnce(ctx)
	if err != nil || st.Sent != 1 || st.Delivered != 1 || host.holds != v || host.applied != 2 {
		t.Fatalf("after the window = %+v, %v, host holds v%d applied %d; want v%d re-sent and applied", st, err, host.holds, host.applied, v)
	}
	if got := m.deliveries["app-0"]; got.Version != v || got.State != store.DeliveryDelivered || !got.UpdatedAt.Equal(clock) || got.Attempts != 1 {
		t.Fatalf("row after the re-send = %+v", got)
	}

	// Next window: the host still holds v, so the re-send changes nothing on
	// it (Applied=false) and only refreshes the row.
	clock = clock.Add(window + time.Minute)
	st, err = d.DeliverOnce(ctx)
	if err != nil || st.Sent != 1 || st.Delivered != 1 || host.holds != v || host.applied != 2 {
		t.Fatalf("second re-send = %+v, %v, host holds v%d applied %d; want harmless", st, err, host.holds, host.applied)
	}
	if got := m.deliveries["app-0"]; got.Version != v || got.State != store.DeliveryDelivered || !got.UpdatedAt.Equal(clock) || got.Attempts != 1 {
		t.Fatalf("row after the harmless re-send = %+v", got)
	}
	if st, _ := d.DeliverOnce(ctx); st.Current != 1 || st.Sent != 0 {
		t.Fatalf("right after the re-send = %+v, want current", st)
	}
}

func TestDeliverOnceWithNoEnvelopeSendsNothing(t *testing.T) {
	t.Parallel()
	hosts := &fakeHosts{}
	d, _ := NewDeliverer(DelivererConfig{Store: &memStore{}, Transport: hosts, Hosts: func() []string { return []string{"app-0"} }})
	if st, err := d.DeliverOnce(context.Background()); err != nil || st.Sent != 0 || len(hosts.sent) != 0 {
		t.Fatalf("DeliverOnce = %+v, %v, sent %v", st, err, hosts.sent)
	}
}
