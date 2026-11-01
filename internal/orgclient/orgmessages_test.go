package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// msgServer is a fake org server for the message rail. It signs REAL
// orgcontract.OrgMessageDoc bodies with orgcontract.SignOrgMessages, the way
// the budget rail's tests sign theirs.
type msgServer struct {
	t    *testing.T
	priv ed25519.PrivateKey

	mu sync.Mutex
	// signAs / signWith override the subject or key the body is signed for
	// (the wrong-subject and wrong-key cases).
	signAs   string
	signWith ed25519.PrivateKey
	// getStatus forces the GET answer when non-zero.
	getStatus int
	// postStatus / postCode force the POST answer when non-zero; dropAck
	// stores the post but answers 500 (a lost acknowledgement).
	postStatus  int
	postCode    string
	dropAck     bool
	pageSize    int
	version     int64
	nextID      int64
	threads     map[string]orgcontract.OrgMessageThreadRow
	messages    []orgcontract.OrgMessageRow
	byClient    map[string]orgcontract.OrgMessagePostResult
	receipts    []orgcontract.OrgMessageReceipt
	gets        int
	conditional int
	posts       int
}

func newMsgServer(t *testing.T, priv ed25519.PrivateKey) (*msgServer, *httptest.Server) {
	ms := &msgServer{
		t: t, priv: priv, pageSize: orgcontract.OrgMessagePageSize, version: 1, nextID: 1,
		threads: map[string]orgcontract.OrgMessageThreadRow{}, byClient: map[string]orgcontract.OrgMessagePostResult{},
	}
	srv := httptest.NewServer(ms)
	t.Cleanup(srv.Close)
	return ms, srv
}

func (ms *msgServer) adminSays(thread, kind, body string, ack bool) int64 {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.threads[thread] = orgcontract.OrgMessageThreadRow{
		ID: thread, Subject: "About " + thread, Kind: kind, StartedBy: "admin", Status: "open",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	id := ms.nextID
	ms.nextID++
	ms.version++
	ms.messages = append(ms.messages, orgcontract.OrgMessageRow{
		ID: id, ThreadID: thread, AuthorKind: orgcontract.OrgMessageAuthorAdmin, AuthorName: "Asha Kim",
		Body: body, RequireAck: ack, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return id
}

func (ms *msgServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == orgcontract.OrgMessagesPath:
		ms.serveGet(w, r)
	case r.Method == http.MethodPost && r.URL.Path == orgcontract.OrgMessagesPath:
		ms.servePost(w, r)
	case r.Method == http.MethodPost && r.URL.Path == orgcontract.OrgMessageReceiptsPath:
		if ms.postStatus != 0 {
			writeTestJSON(w, ms.postStatus, map[string]string{"error": ms.postCode})
			return
		}
		var body orgcontract.OrgMessageReceipts
		_ = json.NewDecoder(r.Body).Decode(&body)
		ms.receipts = append(ms.receipts, body.Receipts...)
		writeTestJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

func (ms *msgServer) serveGet(w http.ResponseWriter, r *http.Request) {
	ms.gets++
	if ms.getStatus != 0 {
		w.WriteHeader(ms.getStatus)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	body := orgcontract.OrgMessageBody{
		Version: ms.version, After: after, NextAfter: after,
		Policy:   orgcontract.OrgMessageNodePolicy{DevThreadsAllowed: true, Topics: []string{"budget", "other"}, RetentionDays: 365},
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
	}
	touched := map[string]bool{}
	for _, m := range ms.messages {
		if m.ID <= after {
			continue
		}
		if len(body.Messages) == ms.pageSize {
			body.More = true
			break
		}
		body.Messages = append(body.Messages, m)
		body.NextAfter = m.ID
		touched[m.ThreadID] = true
	}
	for id := range touched {
		body.Threads = append(body.Threads, ms.threads[id])
	}
	etag, err := orgcontract.OrgMessageDigest(body)
	if err != nil {
		ms.t.Fatal(err)
	}
	etag = `"` + etag + `"`
	if r.Header.Get("If-None-Match") != "" {
		ms.conditional++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	subject, key := "scim-42", ms.priv
	if ms.signAs != "" {
		subject = ms.signAs
	}
	if ms.signWith != nil {
		key = ms.signWith
	}
	doc, err := orgcontract.SignOrgMessages(key, "org-1", subject, body)
	if err != nil {
		ms.t.Fatal(err)
	}
	w.Header().Set("ETag", etag)
	writeTestJSON(w, http.StatusOK, doc)
}

func (ms *msgServer) servePost(w http.ResponseWriter, r *http.Request) {
	ms.posts++
	if ms.postStatus != 0 {
		writeTestJSON(w, ms.postStatus, map[string]string{"error": ms.postCode})
		return
	}
	var p orgcontract.OrgMessagePost
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	if res, ok := ms.byClient[p.ClientMsgID]; ok {
		writeTestJSON(w, http.StatusOK, res)
		return
	}
	thread := p.ThreadID
	if thread == "" {
		thread = "dev-" + p.ClientMsgID
		ms.threads[thread] = orgcontract.OrgMessageThreadRow{
			ID: thread, Subject: p.NewThread.Subject, Kind: "note", Topic: p.NewThread.Topic, StartedBy: "developer", Status: "open",
		}
	}
	res := orgcontract.OrgMessagePostResult{MessageID: ms.nextID, ThreadID: thread}
	ms.nextID++
	ms.version++
	ms.messages = append(ms.messages, orgcontract.OrgMessageRow{
		ID: res.MessageID, ThreadID: thread, AuthorKind: orgcontract.OrgMessageAuthorDeveloper, AuthorName: "Dev",
		Body: p.Body, ClientMsgID: p.ClientMsgID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	ms.byClient[p.ClientMsgID] = res
	if ms.dropAck {
		ms.dropAck = false
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeTestJSON(w, http.StatusCreated, res)
}

// msgClient is an enrolled client whose org key is pinned to pub.
func msgClient(t *testing.T, srvURL string, pub ed25519.PublicKey) (*Client, *store.Store) {
	t.Helper()
	c, st, _ := enrolledClient(t, srvURL)
	pinRoutingKey(t, st, encodeStdKey(pub))
	return c, st
}

func inboxCount(t *testing.T, st *store.Store) int {
	t.Helper()
	threads, err := st.ListOrgMessageThreads(context.Background(), store.OrgMessageThreadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, th := range threads {
		n += th.Messages
	}
	return n
}

func TestSyncOrgMessagesPullsGenuinePagesThenConditional(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ms, srv := newMsgServer(t, priv)
	ms.pageSize = 1
	ms.adminSays("t1", "coaching", "Try a smaller model for routine edits.", false)
	ms.adminSays("t1", "coaching", "Here is a session where it mattered.", true)
	c, st := msgClient(t, srv.URL, pub)
	var sunk []OrgMessageNotice
	c.SetOrgMessageSink(func(m []OrgMessageNotice) { sunk = append(sunk, m...) })

	res, err := c.SyncOrgMessages(context.Background())
	if err != nil || res.State != MessagesFetchOK || res.Received != 2 {
		t.Fatalf("first sync = %+v err=%v", res, err)
	}
	if got := inboxCount(t, st); got != 2 {
		t.Fatalf("stored %d messages, want 2", got)
	}
	if len(sunk) != 2 || sunk[0].Subject != "About t1" || sunk[0].Kind != "coaching" || sunk[0].AuthorName != "Asha Kim" {
		t.Fatalf("sink saw %+v, want two coaching notices with sender and subject", sunk)
	}
	rail, _, _ := st.LoadOrgMessageRail(context.Background())
	if rail.Cursor != 2 || rail.ETag == "" || !rail.Policy.DevThreadsAllowed {
		t.Fatalf("rail = %+v", rail)
	}
	// Nothing new: the stored validator answers 304 and nothing changes.
	res, err = c.SyncOrgMessages(context.Background())
	if err != nil || res.State != MessagesFetchOK || res.Received != 0 || ms.conditional == 0 {
		t.Fatalf("second sync = %+v err=%v conditional=%d", res, err, ms.conditional)
	}
	if len(sunk) != 2 {
		t.Fatalf("a 304 re-notified: %d", len(sunk))
	}
}

func TestSyncOrgMessagesRefusesWhatDoesNotVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name  string
		setup func(ms *msgServer)
	}{
		{"a genuine body for another member", func(ms *msgServer) { ms.signAs = "scim-99" }},
		{"a body signed by another key", func(ms *msgServer) { ms.signWith = otherPriv }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, srv := newMsgServer(t, priv)
			ms.adminSays("t1", "alert", "Stop running that migration.", true)
			tc.setup(ms)
			c, st := msgClient(t, srv.URL, pub)
			res, err := c.SyncOrgMessages(context.Background())
			if err == nil || res.State != MessagesFetchUnverified {
				t.Fatalf("sync = %+v err=%v, want unverified", res, err)
			}
			if got := inboxCount(t, st); got != 0 {
				t.Fatalf("stored %d unverified messages", got)
			}
			rail, _, _ := st.LoadOrgMessageRail(context.Background())
			if rail.FetchState != MessagesFetchUnverified || rail.Cursor != 0 {
				t.Fatalf("rail = %+v", rail)
			}
		})
	}
}

func TestSyncOrgMessagesRefusesVersionRegression(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ms, srv := newMsgServer(t, priv)
	ms.adminSays("t1", "note", "First.", false)
	c, st := msgClient(t, srv.URL, pub)
	if _, err := c.SyncOrgMessages(context.Background()); err != nil {
		t.Fatal(err)
	}
	ms.adminSays("t1", "note", "Second.", false)
	ms.mu.Lock()
	ms.version = 1 // lower than the held version: a replayed lineage
	ms.mu.Unlock()
	res, err := c.SyncOrgMessages(context.Background())
	if err == nil || res.State != MessagesFetchUnverified {
		t.Fatalf("sync = %+v err=%v, want a refused replay", res, err)
	}
	if got := inboxCount(t, st); got != 1 {
		t.Fatalf("stored %d messages, want only the first", got)
	}
}

func TestSyncOrgMessagesLadderKeepsHeldMessages(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		status    int
		wantState string
		wantErr   bool
		backoff   bool
	}{
		{http.StatusNotFound, MessagesFetchNotSupported, false, true},
		{http.StatusNotImplemented, MessagesFetchNotSupported, false, true},
		{http.StatusUnauthorized, MessagesFetchAuthFailed, true, false},
		{http.StatusForbidden, MessagesFetchAuthFailed, true, false},
		{http.StatusConflict, MessagesFetchChannelOff, true, false},
		{http.StatusBadGateway, MessagesFetchUnreachable, true, false},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			ms, srv := newMsgServer(t, priv)
			ms.adminSays("t1", "note", "Kept through anything.", false)
			c, st := msgClient(t, srv.URL, pub)
			if _, err := c.SyncOrgMessages(context.Background()); err != nil {
				t.Fatal(err)
			}
			ms.mu.Lock()
			ms.getStatus = tc.status
			ms.mu.Unlock()
			res, err := c.SyncOrgMessages(context.Background())
			if (err != nil) != tc.wantErr || res.State != tc.wantState {
				t.Fatalf("sync = %+v err=%v, want %s", res, err, tc.wantState)
			}
			if got := inboxCount(t, st); got != 1 {
				t.Fatalf("held messages after %d: %d, want 1", tc.status, got)
			}
			rail, _, _ := st.LoadOrgMessageRail(context.Background())
			if rail.FetchState != tc.wantState || rail.LastOKAt == "" {
				t.Fatalf("rail = %+v", rail)
			}
			if got := c.messages.notFound.Skip(time.Now()); got != tc.backoff {
				t.Fatalf("backoff = %v, want %v", got, tc.backoff)
			}
		})
	}
}

func TestSendOrgMessageIdempotentRetryAfterLostAck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ms, srv := newMsgServer(t, priv)
	ms.adminSays("t1", "coaching", "Can you share the session?", false)
	c, st := msgClient(t, srv.URL, pub)
	if _, err := c.SyncOrgMessages(context.Background()); err != nil {
		t.Fatal(err)
	}
	ms.mu.Lock()
	ms.dropAck = true
	ms.mu.Unlock()
	item, err := c.SendOrgMessage(context.Background(), OrgMessageDraft{ThreadID: "t1", Body: "Sure, attached."})
	if err != nil {
		t.Fatal(err)
	}
	if item.State != store.OrgMessageOutboxQueued || item.Attempts != 1 || item.LastError == "" {
		t.Fatalf("after a lost ack: %+v", item)
	}
	// The next cycle re-posts the same client id: the org answers with the
	// original ids, and the pull brings the one stored copy back.
	if _, err := c.SyncOrgMessages(context.Background()); err != nil {
		t.Fatal(err)
	}
	ms.mu.Lock()
	stored := 0
	for _, m := range ms.messages {
		if m.ClientMsgID == item.ClientMsgID {
			stored++
		}
	}
	ms.mu.Unlock()
	if stored != 1 {
		t.Fatalf("the org stored the reply %d times", stored)
	}
	if _, ok, _ := st.GetOrgMessageOutboxItem(context.Background(), item.ClientMsgID); ok {
		t.Fatal("the outbox row stayed after the stored copy arrived")
	}
	if got := inboxCount(t, st); got != 2 {
		t.Fatalf("inbox = %d, want the admin message and the reply", got)
	}
}

func TestSendOrgMessageRefusalsKeepTheRow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name      string
		status    int
		code      string
		draft     OrgMessageDraft
		wantState string
		wantCode  string
	}{
		{
			"threads disabled", http.StatusForbidden, orgcontract.OrgMessageErrThreadsDisabled,
			OrgMessageDraft{Subject: "Budget", Topic: "budget", Body: "More room?"},
			store.OrgMessageOutboxFailed, orgcontract.OrgMessageErrThreadsDisabled,
		},
		{
			"topic not allowed", http.StatusForbidden, orgcontract.OrgMessageErrTopicNotAllowed,
			OrgMessageDraft{Subject: "Guard", Topic: "guard", Body: "Why blocked?"},
			store.OrgMessageOutboxFailed, orgcontract.OrgMessageErrTopicNotAllowed,
		},
		{
			"thread not found", http.StatusNotFound, orgcontract.OrgMessageErrNotFound,
			OrgMessageDraft{ThreadID: "gone", Body: "Hello?"},
			store.OrgMessageOutboxFailed, orgcontract.OrgMessageErrNotFound,
		},
		{
			"bad request", http.StatusBadRequest, "",
			OrgMessageDraft{ThreadID: "t1", Body: "x"},
			store.OrgMessageOutboxFailed, "",
		},
		{
			"auth without a code stays queued", http.StatusForbidden, "",
			OrgMessageDraft{ThreadID: "t1", Body: "x"},
			store.OrgMessageOutboxQueued, "",
		},
		{
			"server error stays queued", http.StatusServiceUnavailable, "",
			OrgMessageDraft{ThreadID: "t1", Body: "x"},
			store.OrgMessageOutboxQueued, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, srv := newMsgServer(t, priv)
			c, _ := msgClient(t, srv.URL, pub)
			ms.postStatus, ms.postCode = tc.status, tc.code
			item, err := c.SendOrgMessage(context.Background(), tc.draft)
			if err != nil {
				t.Fatal(err)
			}
			if item.State != tc.wantState || item.LastErrorCode != tc.wantCode || item.LastError == "" {
				t.Fatalf("item = %+v", item)
			}
		})
	}
}

func TestClassifyPostAnswerRows(t *testing.T) {
	cases := []struct {
		status    int
		code      string
		want      postVerdict
		wantState string
	}{
		{http.StatusCreated, "", postAccepted, MessagesFetchOK},
		{http.StatusOK, "", postAccepted, MessagesFetchOK},
		{http.StatusForbidden, orgcontract.OrgMessageErrThreadsDisabled, postRefused, ""},
		{http.StatusConflict, orgcontract.OrgMessageErrThreadClosed, postRefused, ""},
		{http.StatusConflict, "", postRetry, MessagesFetchChannelOff},
		{http.StatusUnprocessableEntity, "", postRefused, ""},
		{http.StatusUnauthorized, "", postRetry, MessagesFetchAuthFailed},
		{http.StatusNotFound, "", postRetry, MessagesFetchNotSupported},
		{http.StatusInternalServerError, "", postRetry, MessagesFetchUnreachable},
	}
	for _, tc := range cases {
		got := classifyPostAnswer(tc.status, tc.code)
		if got.verdict != tc.want || got.state != tc.wantState {
			t.Errorf("classify(%d, %q) = %+v, want %v/%q", tc.status, tc.code, got, tc.want, tc.wantState)
		}
	}
}

func TestReadReceiptsFollowTenancyAndSetting(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name         string
		tenancy      string
		localSetting bool
		wantReads    int
	}{
		{"individual, receipts on", "", true, 1},
		{"individual, receipts off", "", false, 0},
		{"managed ignores the local switch", orgcontract.TenancyManaged, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, srv := newMsgServer(t, priv)
			ms.adminSays("t1", "alert", "Please acknowledge.", true)
			c, st := msgClient(t, srv.URL, pub)
			ctx := context.Background()
			enr, _ := st.LoadEnrolment(ctx)
			enr.Tenancy = tc.tenancy
			if err := st.WriteEnrolment(ctx, *enr); err != nil {
				t.Fatal(err)
			}
			setting := config.DefaultMessagesConfig()
			setting.ReadReceipts = tc.localSetting
			c.SetMessagesSettings(func() config.MessagesConfig { return setting })
			if _, err := c.SyncOrgMessages(ctx); err != nil {
				t.Fatal(err)
			}
			if n, err := c.MarkOrgMessageThreadRead(ctx, "t1"); err != nil || n != 1 {
				t.Fatalf("read: n=%d err=%v", n, err)
			}
			if _, err := c.AckOrgMessage(ctx, 1); err != nil {
				t.Fatal(err)
			}
			ms.mu.Lock()
			defer ms.mu.Unlock()
			reads, acks := 0, 0
			for _, r := range ms.receipts {
				switch r.State {
				case orgcontract.OrgMessageReceiptRead:
					reads++
				case orgcontract.OrgMessageReceiptAcknowledged:
					acks++
				}
			}
			if reads != tc.wantReads || acks != 1 {
				t.Fatalf("receipts: read=%d acknowledged=%d, want %d/1", reads, acks, tc.wantReads)
			}
		})
	}
}

func TestSendOrgMessageRefusedOnAnOlderServer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ms, srv := newMsgServer(t, priv)
	ms.getStatus = http.StatusNotFound
	c, _ := msgClient(t, srv.URL, pub)
	if res, err := c.SyncOrgMessages(context.Background()); err != nil || res.State != MessagesFetchNotSupported {
		t.Fatalf("sync = %+v err=%v", res, err)
	}
	if _, err := c.SendOrgMessage(context.Background(), OrgMessageDraft{Subject: "s", Topic: "other", Body: "x"}); !errors.Is(err, ErrOrgMessagesUnavailable) {
		t.Fatalf("send on an older server err = %v", err)
	}
}

// TestStalledMessageRailRetriesWhenTheOrgAnswers pins bug 1 of the T-854
// review: a reply queued while the org was down used to wait for the next
// full push cycle (minutes after a long outage). Now any request the org
// answers (a light push, a policy-version probe) retries the stalled rail at
// once. Each row is one trigger.
func TestStalledMessageRailRetriesWhenTheOrgAnswers(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		// restart drops the in-memory stall mark, as a daemon restart during
		// the outage does: the queued outbox row alone must count.
		restart bool
		trigger func(c *Client)
		want    bool
	}{
		{"probe 304", false, func(c *Client) { c.finishProbe(context.Background(), probeAnswer{status: http.StatusNotModified}) }, true},
		{"probe 404 from an older server", false, func(c *Client) { c.finishProbe(context.Background(), probeAnswer{status: http.StatusNotFound}) }, true},
		{"direct retry after a restart", true, func(c *Client) { c.retryStalledOrgMessages(context.Background()) }, true},
		{"failed probe does not retry", false, func(c *Client) {
			c.finishProbe(context.Background(), probeAnswer{err: errors.New("dial tcp: connection refused")})
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms, srv := newMsgServer(t, priv)
			ms.adminSays("t1", "coaching", "Can you share the session?", false)
			c, st := msgClient(t, srv.URL, pub)
			if _, err := c.SyncOrgMessages(context.Background()); err != nil {
				t.Fatal(err)
			}
			// The org goes down: the reply is queued and the rail stalls.
			ms.mu.Lock()
			ms.postStatus = http.StatusServiceUnavailable
			ms.mu.Unlock()
			item, err := c.SendOrgMessage(context.Background(), OrgMessageDraft{ThreadID: "t1", Body: "Sure, attached."})
			if err != nil {
				t.Fatal(err)
			}
			if item.State != store.OrgMessageOutboxQueued || !c.messages.stalled.Load() {
				t.Fatalf("after the outage: item %+v stalled=%v", item, c.messages.stalled.Load())
			}
			if tc.restart {
				c.messages.stalled.Store(false)
			}
			// The org comes back.
			ms.mu.Lock()
			ms.postStatus = 0
			ms.mu.Unlock()
			tc.trigger(c)
			_, stillQueued, _ := st.GetOrgMessageOutboxItem(context.Background(), item.ClientMsgID)
			if delivered := !stillQueued; delivered != tc.want {
				t.Fatalf("delivered = %v, want %v", delivered, tc.want)
			}
			if !tc.want {
				return
			}
			if got := inboxCount(t, st); got != 2 {
				t.Fatalf("inbox = %d, want the admin message and the reply", got)
			}
			if c.messages.stalled.Load() {
				t.Fatal("a clean sync left the rail marked stalled")
			}
			// Nothing stalled and nothing queued: the next answer costs no sync.
			ms.mu.Lock()
			gets := ms.gets
			ms.mu.Unlock()
			if c.retryStalledOrgMessages(context.Background()) {
				t.Fatal("retried a healthy rail")
			}
			ms.mu.Lock()
			defer ms.mu.Unlock()
			if ms.gets != gets {
				t.Fatalf("a healthy rail was pulled again (%d -> %d)", gets, ms.gets)
			}
		})
	}
}
