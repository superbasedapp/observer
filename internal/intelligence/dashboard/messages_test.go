package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeMessages is a dashapi.MessageService over the real node-local store:
// it does what the org client does locally and never touches a network.
type fakeMessages struct {
	st       *store.Store
	enrolled bool
	receipts bool
	sendErr  error
	sent     []orgclient.OrgMessageDraft
	nudges   int
}

func (f *fakeMessages) Status(context.Context) (orgclient.EnrolmentState, error) {
	return orgclient.EnrolmentState{Enrolled: f.enrolled, OrgName: "Acme", OrgID: "org-1"}, nil
}

func (f *fakeMessages) SendOrgMessage(ctx context.Context, d orgclient.OrgMessageDraft) (store.OrgMessageOutboxItem, error) {
	if f.sendErr != nil {
		return store.OrgMessageOutboxItem{}, f.sendErr
	}
	f.sent = append(f.sent, d)
	id := d.ClientMsgID
	if id == "" {
		id = "c-" + time.Now().Format("150405.000000000")
	}
	return f.st.EnqueueOrgMessagePost(ctx, store.OrgMessagePostDraft{
		ClientMsgID: id, OrgID: "org-1", ThreadID: d.ThreadID, NewSubject: d.Subject, NewTopic: d.Topic,
		Body: d.Body, Attachments: d.Attachments,
	})
}

func (f *fakeMessages) RetryOrgMessage(ctx context.Context, id string) (store.OrgMessageOutboxItem, error) {
	item, ok, err := f.st.GetOrgMessageOutboxItem(ctx, id)
	if err != nil {
		return item, err
	}
	if !ok {
		return item, store.ErrOrgMessageNotFound
	}
	_, _ = f.st.RequeueOrgMessageOutbox(ctx, id)
	item.State = store.OrgMessageOutboxQueued
	return item, nil
}

func (f *fakeMessages) DiscardOrgMessage(ctx context.Context, id string) (bool, error) {
	return f.st.DiscardOrgMessageOutbox(ctx, id)
}

func (f *fakeMessages) MarkOrgMessageThreadRead(ctx context.Context, id string) (int, error) {
	return f.st.MarkOrgMessageThreadRead(ctx, id, "org-1", f.receipts, time.Now())
}

func (f *fakeMessages) AckOrgMessage(ctx context.Context, id int64) (store.OrgInboxMessage, error) {
	return f.st.AckOrgMessage(ctx, id, "org-1", time.Now())
}

func (f *fakeMessages) OrgMessageReadReceiptsOn(context.Context) bool { return f.receipts }

func (f *fakeMessages) NoteActivity() { f.nudges++ }

// newMessagesServer is a test server holding one coaching thread and one
// alert thread from an admin, with the policy allowing budget and other.
func newMessagesServer(t *testing.T, enrolled bool) (*Server, *fakeMessages) {
	t.Helper()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	if _, err := st.SaveOrgMessagePage(context.Background(), store.OrgMessagePage{
		OrgID: "org-1", Subject: "scim-42", KeyFingerprint: "fp", Now: time.Now(),
		Body: orgcontract.OrgMessageBody{
			Version: 2, NextAfter: 2,
			Policy: orgcontract.OrgMessageNodePolicy{DevThreadsAllowed: true, Topics: []string{"budget", "other"}, RetentionDays: 365},
			Threads: []orgcontract.OrgMessageThreadRow{
				{ID: "t1", Subject: "Model choice", Kind: "coaching", StartedBy: "admin", Status: "open"},
				{ID: "t2", Subject: "Stop the migration", Kind: "alert", StartedBy: "admin", Status: "open"},
			},
			Messages: []orgcontract.OrgMessageRow{
				{ID: 1, ThreadID: "t1", AuthorKind: "admin", AuthorName: "Asha Kim", Body: "Try a smaller model.", CreatedAt: time.Now().UTC().Format(time.RFC3339)},
				{ID: 2, ThreadID: "t2", AuthorKind: "admin", AuthorName: "Asha Kim", Body: "Please stop.", RequireAck: true, CreatedAt: time.Now().UTC().Format(time.RFC3339)},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	f := &fakeMessages{st: st, enrolled: enrolled, receipts: true}
	s.opts.Messages = f
	return s, f
}

func postMessages(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, armLocalWrite(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))))
	return rr
}

func TestMessagesListShowsThreadsRailAndPolicy(t *testing.T) {
	s, _ := newMessagesServer(t, true)
	var out messagesPageResponse
	getModelJSON(t, s, "/api/messages", &out)
	if !out.Enrolled || out.Rail.State != messagesRailOK || !out.AskAllowed || out.Policy == nil || !out.ReadReceipts {
		t.Fatalf("page = %+v", out)
	}
	if len(out.Threads) != 2 || out.Summary.Unread != 2 || out.Summary.NeedsAck != 1 || out.ConfirmToken == "" {
		t.Fatalf("threads=%d summary=%+v", len(out.Threads), out.Summary)
	}
	if !out.Surfaces.Toast || out.Surfaces.Desktop {
		t.Fatalf("default surfaces = %+v", out.Surfaces)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/messages?status=bogus", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad status filter = %d", rr.Code)
	}
}

func TestMessagesRailStateMapping(t *testing.T) {
	cases := []struct {
		enrolled bool
		fetch    string
		want     string
	}{
		{false, orgclient.MessagesFetchOK, messagesRailNotEnrolled},
		{true, "", messagesRailPending},
		{true, orgclient.MessagesFetchOK, messagesRailOK},
		{true, orgclient.MessagesFetchNotSupported, messagesRailNotSupported},
		{true, orgclient.MessagesFetchChannelOff, messagesRailChannelOff},
		{true, orgclient.MessagesFetchAuthFailed, messagesRailOffline},
		{true, orgclient.MessagesFetchUnreachable, messagesRailOffline},
		{true, orgclient.MessagesFetchUnverified, messagesRailOffline},
		{true, "something_new", messagesRailOffline},
	}
	for _, c := range cases {
		mc := messagesContext{enrolled: c.enrolled, rail: store.OrgMessageRail{FetchState: c.fetch}}
		if got := mc.railView().State; got != c.want {
			t.Errorf("enrolled=%v fetch=%q -> %q, want %q", c.enrolled, c.fetch, got, c.want)
		}
	}
}

func TestMessagesNotEnrolled(t *testing.T) {
	s, _ := newMessagesServer(t, false)
	var out messagesPageResponse
	getModelJSON(t, s, "/api/messages", &out)
	if out.Enrolled || out.Rail.State != messagesRailNotEnrolled || out.AskAllowed {
		t.Fatalf("page = %+v", out)
	}
	rr := postMessages(t, s, "/api/messages", `{"thread_id":"t1","body":"hi"}`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), messagesRailNotEnrolled) {
		t.Fatalf("send when not enrolled = %d %s", rr.Code, rr.Body.String())
	}
}

func TestMessagesSendReplyAndAskMyAdmin(t *testing.T) {
	s, f := newMessagesServer(t, true)
	cases := []struct {
		name     string
		body     string
		wantCode int
		wantText string
	}{
		{"reply", `{"thread_id":"t1","body":"Will do."}`, http.StatusOK, `"state":"queued"`},
		{"ask my admin", `{"subject":"More budget","topic":"budget","body":"Can I have more room?"}`, http.StatusOK, `"new_subject":"More budget"`},
		{"topic outside the org's list", `{"subject":"Guard","topic":"guard","body":"Why?"}`, http.StatusForbidden, orgcontract.OrgMessageErrTopicNotAllowed},
		{"empty body", `{"thread_id":"t1","body":"  "}`, http.StatusBadRequest, "invalid"},
		{"not json", `nope`, http.StatusBadRequest, "bad_request"},
	}
	for _, tc := range cases {
		rr := postMessages(t, s, "/api/messages", tc.body)
		if rr.Code != tc.wantCode || !strings.Contains(rr.Body.String(), tc.wantText) {
			t.Fatalf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
	}
	if len(f.sent) != 3 { // the topic refusal never reached the service
		t.Fatalf("service saw %d sends", len(f.sent))
	}
	f.sendErr = orgclient.ErrOrgMessagesUnavailable
	if rr := postMessages(t, s, "/api/messages", `{"thread_id":"t1","body":"x"}`); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), messagesRailNotSupported) {
		t.Fatalf("older server = %d %s", rr.Code, rr.Body.String())
	}
	var out messagesPageResponse
	getModelJSON(t, s, "/api/messages", &out)
	if len(out.PendingThreads) != 1 || out.PendingThreads[0].NewSubject != "More budget" {
		t.Fatalf("pending threads = %+v", out.PendingThreads)
	}
}

func TestMessagesThreadReadAckDiscard(t *testing.T) {
	s, _ := newMessagesServer(t, true)
	var th messageThreadResponse
	getModelJSON(t, s, "/api/messages/threads/t2", &th)
	if th.Thread.ID != "t2" || len(th.Messages) != 1 || !th.ReadReceipts {
		t.Fatalf("thread = %+v", th)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/messages/threads/nope", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown thread = %d", rr.Code)
	}

	steps := []struct {
		name     string
		path     string
		wantCode int
		wantText string
	}{
		{"read", "/api/messages/threads/t2/read", http.StatusOK, `"marked":1`},
		{"read again", "/api/messages/threads/t2/read", http.StatusOK, `"marked":0`},
		{"read unknown", "/api/messages/threads/nope/read", http.StatusNotFound, ""},
		{"ack one that did not ask", "/api/messages/1/ack", http.StatusConflict, "not_requested"},
		{"ack", "/api/messages/2/ack", http.StatusOK, `"acked_at"`},
		{"ack unknown", "/api/messages/99/ack", http.StatusNotFound, ""},
		{"discard unknown", "/api/messages/outbox/nope/discard", http.StatusNotFound, ""},
	}
	for _, st := range steps {
		rr := postMessages(t, s, st.path, "")
		if rr.Code != st.wantCode || !strings.Contains(rr.Body.String(), st.wantText) {
			t.Fatalf("%s: %d %s", st.name, rr.Code, rr.Body.String())
		}
	}
	rr = postMessages(t, s, "/api/messages", `{"client_msg_id":"c-9","thread_id":"t1","body":"x"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("send: %d", rr.Code)
	}
	if rr := postMessages(t, s, "/api/messages/outbox/c-9/discard", ""); rr.Code != http.StatusNoContent {
		t.Fatalf("discard = %d %s", rr.Code, rr.Body.String())
	}
}

func TestMessagesSummaryAndBell(t *testing.T) {
	s, _ := newMessagesServer(t, true)
	var sum messagesSummaryResponse
	getModelJSON(t, s, "/api/messages/summary", &sum)
	if sum.Unread != 2 || sum.UnreadAlerts != 1 || sum.Push.Unread != 2 || sum.Push.Newest == nil || sum.Newest.ThreadID != "t2" {
		t.Fatalf("summary = %+v", sum)
	}
	if got := pushView(sum.OrgMessageSummary, true); got.Unread != 1 || got.Newest == nil || got.Newest.Kind != "alert" {
		t.Fatalf("alerts-only push view = %+v", got)
	}

	r := getNotifications(t, s)
	found := 0
	for _, n := range r.Notifications {
		if strings.HasPrefix(n.ID, "org_message:") {
			found++
			if !strings.Contains(n.Title, "Asha Kim (admin):") || !strings.HasPrefix(n.Link, "/messages?thread=") {
				t.Fatalf("bell row = %+v", n)
			}
		}
	}
	if found != 2 {
		t.Fatalf("bell has %d message rows, want 2", found)
	}

	var tile StatuslineResponse
	getModelJSON(t, s, "/api/statusline", &tile)
	if tile.MessagesUnread != 2 || tile.MessagesUnreadAlerts != 1 {
		t.Fatalf("statusline tile = %+v", tile)
	}
}

// TestMessagesOrgName pins the naming rule (T-854 review): the page says
// "the admins of <name>", and a bare host only stands in when the org gave
// no name at all.
func TestMessagesOrgName(t *testing.T) {
	cases := []struct {
		name, notice, enrolled, server, want string
	}{
		{"governance notice wins", "Acme Payments", "acme-org", "https://org.acme.example", "Acme Payments"},
		{"enrolment name", "", "Acme", "https://org.acme.example", "Acme"},
		{"whitespace is no name", "  ", " ", "http://127.0.0.1:18443", "127.0.0.1:18443"},
		{"host only when nothing names it", "", "", "https://org.acme.example/base", "org.acme.example"},
		{"nothing known", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := messagesOrgName(tc.notice, tc.enrolled, tc.server); got != tc.want {
				t.Fatalf("messagesOrgName = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMessagesWaitingOnOrg pins when the page nudges the org client (T-854
// bug 1): an offline rail or a queued post, nothing else.
func TestMessagesWaitingOnOrg(t *testing.T) {
	queued := []store.OrgMessageOutboxItem{{State: store.OrgMessageOutboxQueued}}
	failed := []store.OrgMessageOutboxItem{{State: store.OrgMessageOutboxFailed}}
	cases := []struct {
		name  string
		rail  string
		posts []store.OrgMessageOutboxItem
		want  bool
	}{
		{"offline rail", messagesRailOffline, nil, true},
		{"queued reply", messagesRailOK, queued, true},
		{"refused reply waits for the developer, not the org", messagesRailOK, failed, false},
		{"healthy and empty", messagesRailOK, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := messagesWaitingOnOrg(tc.rail, tc.posts); got != tc.want {
				t.Fatalf("messagesWaitingOnOrg = %v, want %v", got, tc.want)
			}
		})
	}
}
