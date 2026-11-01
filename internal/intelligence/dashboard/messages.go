package dashboard

// messages.go: the node dashboard's half of admin and developer messaging
// (docs/plans/admin-developer-messaging-plan-2026-10-15.md sections 8 and
// 17.6, T-854). Every route is owner-local (refused on a remote view) and
// every write echoes the double-submit confirm token, the notifications.go
// discipline.
//
//	GET  /api/messages                         threads + rail status + policy + surfaces
//	POST /api/messages                         reply or "Ask my admin" (outbox, then send now)
//	GET  /api/messages/summary                 counts + newest (VS Code, nav badge)
//	GET  /api/messages/threads/{id}            one conversation
//	POST /api/messages/threads/{id}/read       mark read (queues read receipts when on)
//	POST /api/messages/{id}/ack                acknowledge one admin message
//	POST /api/messages/outbox/{id}/retry       resend a refused post
//	POST /api/messages/outbox/{id}/discard     drop a post the org has not accepted
//
// The reads come from the node-local tables (internal/store/orgmessages.go)
// and never reach the network; only the writes go through the injected
// dashapi.MessageService (the org client), which sends at once and leaves
// anything it cannot send queued for the next cycle.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/notify/feed"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Rail states the Messages page renders (a closed set).
const (
	messagesRailNotEnrolled  = "not_enrolled"
	messagesRailPending      = "pending"
	messagesRailOK           = "ok"
	messagesRailOffline      = "offline"
	messagesRailNotSupported = "not_supported"
	messagesRailChannelOff   = "channel_off"
)

// messagesRailStates maps the org client's fetch state onto what the page
// says (CLAUDE.md #5): a credential refusal, an outage and a refused
// document all read as "offline, last contact ...", because to the
// developer they mean the same thing: new messages are not arriving.
var messagesRailStates = map[string]string{
	"":                                  messagesRailPending,
	orgclient.MessagesFetchOK:           messagesRailOK,
	orgclient.MessagesFetchNotSupported: messagesRailNotSupported,
	orgclient.MessagesFetchChannelOff:   messagesRailChannelOff,
	orgclient.MessagesFetchAuthFailed:   messagesRailOffline,
	orgclient.MessagesFetchUnreachable:  messagesRailOffline,
	orgclient.MessagesFetchUnverified:   messagesRailOffline,
}

// messagesRailView is the rail block of GET /api/messages and the summary.
type messagesRailView struct {
	State         string `json:"state"`
	FetchState    string `json:"fetch_state,omitempty"`
	LastOKAt      string `json:"last_ok_at,omitempty"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

// messagesSurfaces is the developer's [messages] choice, echoed so the
// dashboard (toast) and VS Code know whether to surface anything.
type messagesSurfaces struct {
	Toast        bool `json:"toast"`
	VSCode       bool `json:"vscode"`
	Statusline   bool `json:"statusline"`
	Desktop      bool `json:"desktop"`
	AlertsOnly   bool `json:"alerts_only"`
	ReadReceipts bool `json:"read_receipts"`
	// ReadReceiptsLocked: this machine's enrolment is organization-managed,
	// so read receipts are always sent whatever read_receipts says (the
	// enterprise full-capture ruling, orgclient readReceiptsOn). The Settings
	// card shows the switch fixed on and says why.
	ReadReceiptsLocked bool `json:"read_receipts_locked"`
}

func surfacesOf(m config.MessagesConfig, managed bool) messagesSurfaces {
	return messagesSurfaces{
		Toast: m.Toast, VSCode: m.VSCode, Statusline: m.Statusline, Desktop: m.Desktop,
		AlertsOnly: m.AlertsOnly, ReadReceipts: m.ReadReceipts, ReadReceiptsLocked: managed,
	}
}

// messagesPageResponse is GET /api/messages.
type messagesPageResponse struct {
	Enrolled bool             `json:"enrolled"`
	OrgName  string           `json:"org_name,omitempty"`
	Rail     messagesRailView `json:"rail"`
	// Policy is the developer-facing org policy from the last verified pull
	// (null until one arrived).
	Policy *orgcontract.OrgMessageNodePolicy `json:"policy"`
	// AskAllowed: the page may offer "Ask my admin" (enrolled, the org
	// serves messaging, and its policy lets this developer start threads).
	AskAllowed bool `json:"ask_allowed"`
	// ReadReceipts: the developer's admins can see when they read a message
	// (the thread footer says so).
	ReadReceipts bool                            `json:"read_receipts"`
	Surfaces     messagesSurfaces                `json:"surfaces"`
	Threads      []store.OrgMessageThreadSummary `json:"threads"`
	// PendingThreads are developer-started conversations the org has not
	// stored yet (queued, refused, or sent and waiting for the next pull).
	PendingThreads []store.OrgMessageOutboxItem `json:"pending_threads"`
	Summary        store.OrgMessageSummary      `json:"summary"`
	GeneratedAt    string                       `json:"generated_at"`
	ConfirmToken   string                       `json:"confirm_token"`
}

// messagesContext is what every handler needs to know about this node.
type messagesContext struct {
	enrolled bool
	orgName  string
	rail     store.OrgMessageRail
	haveRail bool
	cfg      config.MessagesConfig
	// managed: the enrolment is organization-managed (read receipts are
	// then always on).
	managed bool
}

func (s *Server) messagesContext(ctx context.Context) messagesContext {
	mc := messagesContext{cfg: config.DefaultMessagesConfig()}
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		mc.cfg = cfg.Messages
	}
	if svc := s.opts.Messages; svc != nil {
		if st, err := svc.Status(ctx); err == nil && st.Enrolled {
			notice := ""
			if s.opts.Governance != nil {
				notice = s.opts.Governance(ctx).Notice.OrgDisplayName
			}
			mc.enrolled, mc.orgName = true, messagesOrgName(notice, st.OrgName, st.OrgServerURL)
		}
	}
	if s.db() != nil {
		if r, ok, err := store.New(s.db()).LoadOrgMessageRail(ctx); err == nil {
			mc.rail, mc.haveRail = r, ok
		}
		if mc.enrolled {
			// Managed by enrolment or by its org's switch to enterprise (P-204).
			if managed, err := orgclient.NodeManaged(ctx, store.New(s.db())); err == nil {
				mc.managed = managed
			}
		}
	}
	return mc
}

// messagesOrgName is the one rule for naming the organization on the
// Messages page and in Ask my admin: the display name the org signed into
// this machine's governance notice, else the name the org gave at
// enrolment, and the server's host only when neither names it. Empty means
// nothing is known (the page then says "your organization").
func messagesOrgName(noticeName, enrolledName, serverURL string) string {
	for _, c := range []string{noticeName, enrolledName} {
		if name := strings.TrimSpace(c); name != "" {
			return name
		}
	}
	if u, err := url.Parse(strings.TrimSpace(serverURL)); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

func (mc messagesContext) railView() messagesRailView {
	if !mc.enrolled {
		return messagesRailView{State: messagesRailNotEnrolled}
	}
	state, ok := messagesRailStates[mc.rail.FetchState]
	if !ok {
		state = messagesRailOffline
	}
	return messagesRailView{
		State: state, FetchState: mc.rail.FetchState, LastOKAt: mc.rail.LastOKAt,
		LastAttemptAt: mc.rail.LastAttemptAt, LastError: mc.rail.LastError,
	}
}

// askAllowed is the one rule for offering "Ask my admin".
func (mc messagesContext) askAllowed() bool {
	if !mc.enrolled || !mc.haveRail || !mc.rail.HavePolicy {
		return false
	}
	switch mc.railView().State {
	case messagesRailNotSupported, messagesRailChannelOff:
		return false
	}
	return mc.rail.Policy.DevThreadsAllowed
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleMessagesList(w, r)
	case http.MethodPost:
		s.handleMessagesSend(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleMessagesList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	mc := s.messagesContext(ctx)
	out := messagesPageResponse{
		Enrolled: mc.enrolled, OrgName: mc.orgName, Rail: mc.railView(), AskAllowed: mc.askAllowed(),
		Surfaces: surfacesOf(mc.cfg, mc.managed), Threads: []store.OrgMessageThreadSummary{},
		PendingThreads: []store.OrgMessageOutboxItem{}, GeneratedAt: s.now().UTC().Format(time.RFC3339),
		ConfirmToken: setConfirmCookie(w, r),
	}
	if mc.haveRail && mc.rail.HavePolicy {
		p := mc.rail.Policy
		out.Policy = &p
	}
	if svc := s.opts.Messages; svc != nil && mc.enrolled {
		out.ReadReceipts = svc.OrgMessageReadReceiptsOn(ctx)
	}
	if s.db() == nil {
		writeJSON(w, out)
		return
	}
	st := store.New(s.db())
	status := r.URL.Query().Get("status")
	if status == "all" {
		status = ""
	}
	if status != "" && status != "open" && status != "closed" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": `status must be "open", "closed" or "all"`})
		return
	}
	threads, err := st.ListOrgMessageThreads(ctx, store.OrgMessageThreadFilter{Status: status})
	if err != nil {
		writeErr(w, err)
		return
	}
	out.Threads = threads
	posts, err := st.ListOrgMessageOutboxPosts(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, p := range posts {
		if p.ThreadID == "" {
			out.PendingThreads = append(out.PendingThreads, p)
		}
	}
	if out.Summary, err = st.OrgMessageSummary(ctx); err != nil {
		writeErr(w, err)
		return
	}
	// The developer is looking at the page while something waits on the
	// org (the rail is offline, or a reply is still queued): nudge the org
	// client, so the moment the org answers again the queued reply goes
	// out, instead of on the next push cycle (T-854).
	if svc := s.opts.Messages; svc != nil && mc.enrolled && messagesWaitingOnOrg(out.Rail.State, posts) {
		svc.NoteActivity()
	}
	writeJSON(w, out)
}

// messagesWaitingOnOrg reports whether the page shows something only the
// org's return can move: an offline rail or a queued post.
func messagesWaitingOnOrg(railState string, posts []store.OrgMessageOutboxItem) bool {
	if railState == messagesRailOffline {
		return true
	}
	for _, p := range posts {
		if p.State == store.OrgMessageOutboxQueued {
			return true
		}
	}
	return false
}

// messagesSendBody is POST /api/messages.
type messagesSendBody struct {
	ClientMsgID string                             `json:"client_msg_id"`
	ThreadID    string                             `json:"thread_id"`
	Subject     string                             `json:"subject"`
	Topic       string                             `json:"topic"`
	Body        string                             `json:"body"`
	Attachments []orgcontract.OrgMessageAttachment `json:"attachments"`
}

// messagesError writes the {error, message} shape every route refuses with.
func messagesError(w http.ResponseWriter, status int, code, msg string) {
	writeJSONStatus(w, status, map[string]string{"error": code, "message": msg})
}

// preCheckNewThread applies the org's own policy before a new conversation
// is queued, so the developer hears "not allowed" now rather than a refused
// row later. The org re-checks on POST; this only shapes the answer.
func preCheckNewThread(mc messagesContext, topic string) (code, msg string, ok bool) {
	if !mc.haveRail || !mc.rail.HavePolicy {
		return "", "", true // nothing verified yet: let the org decide
	}
	if !mc.rail.Policy.DevThreadsAllowed {
		return orgcontract.OrgMessageErrThreadsDisabled, "your organization does not let you start conversations", false
	}
	if len(mc.rail.Policy.Topics) > 0 && !slices.Contains(mc.rail.Policy.Topics, topic) {
		return orgcontract.OrgMessageErrTopicNotAllowed, "your organization does not take messages on this topic", false
	}
	return "", "", true
}

func (s *Server) handleMessagesSend(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	svc := s.opts.Messages
	if svc == nil {
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "messages go to an organization; this machine is not enrolled")
		return
	}
	var body messagesSendBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		messagesError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	ctx := r.Context()
	mc := s.messagesContext(ctx)
	if !mc.enrolled {
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "messages go to an organization; this machine is not enrolled")
		return
	}
	newThread := strings.TrimSpace(body.ThreadID) == ""
	if newThread {
		if code, msg, ok := preCheckNewThread(mc, strings.TrimSpace(body.Topic)); !ok {
			messagesError(w, http.StatusForbidden, code, msg)
			return
		}
	}
	item, err := svc.SendOrgMessage(ctx, orgclient.OrgMessageDraft{
		ClientMsgID: body.ClientMsgID, ThreadID: body.ThreadID, Subject: body.Subject, Topic: body.Topic,
		Body: body.Body, Attachments: body.Attachments,
	})
	switch {
	case errors.Is(err, orgclient.ErrNotEnrolled):
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "messages go to an organization; this machine is not enrolled")
		return
	case errors.Is(err, orgclient.ErrOrgMessagesUnavailable):
		messagesError(w, http.StatusConflict, messagesRailNotSupported, "your organization's server does not support messages yet")
		return
	case errors.Is(err, store.ErrOrgMessageInvalid):
		messagesError(w, http.StatusBadRequest, "invalid", strings.TrimPrefix(err.Error(), store.ErrOrgMessageInvalid.Error()+": "))
		return
	case errors.Is(err, store.ErrOrgMessageOutboxFull):
		messagesError(w, http.StatusTooManyRequests, "outbox_full", "too many messages are waiting to be sent; discard one or wait until your organization is reachable")
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	kind := "reply"
	if newThread {
		kind = "new_thread"
	}
	s.recordManageAudit(r, "messages_send", fmt.Sprintf("kind=%s state=%s attachments=%d", kind, item.State, len(item.Attachments)))
	writeJSON(w, map[string]any{"item": item})
}

// handleMessagesSub routes /api/messages/... .
func (s *Server) handleMessagesSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/messages/"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "summary":
		s.handleMessagesSummary(w, r)
	case len(parts) == 2 && parts[0] == "threads":
		s.handleMessageThread(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "threads" && parts[2] == "read":
		s.handleMessageThreadRead(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "outbox" && parts[2] == "discard":
		s.handleMessageOutboxDiscard(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "outbox" && parts[2] == "retry":
		s.handleMessageOutboxRetry(w, r, parts[1])
	case len(parts) == 2 && parts[1] == "ack":
		s.handleMessageAck(w, r, parts[0])
	default:
		http.NotFound(w, r)
	}
}

// messageThreadResponse is GET /api/messages/threads/{id}.
type messageThreadResponse struct {
	store.OrgMessageThread
	ReadReceipts bool             `json:"read_receipts"`
	Rail         messagesRailView `json:"rail"`
	ConfirmToken string           `json:"confirm_token"`
}

func (s *Server) handleMessageThread(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.db() == nil || !messageIDOK(id) {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	th, ok, err := store.New(s.db()).GetOrgMessageThread(ctx, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	mc := s.messagesContext(ctx)
	out := messageThreadResponse{OrgMessageThread: th, Rail: mc.railView(), ConfirmToken: setConfirmCookie(w, r)}
	if svc := s.opts.Messages; svc != nil && mc.enrolled {
		out.ReadReceipts = svc.OrgMessageReadReceiptsOn(ctx)
	}
	writeJSON(w, out)
}

func (s *Server) handleMessageThreadRead(w http.ResponseWriter, r *http.Request, id string) {
	if !requireConfirmToken(w, r) {
		return
	}
	if !messageIDOK(id) {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	var (
		n   int
		err error
	)
	receipts := false
	if svc := s.opts.Messages; svc != nil {
		n, err = svc.MarkOrgMessageThreadRead(ctx, id)
		receipts = svc.OrgMessageReadReceiptsOn(ctx)
	} else if s.db() != nil {
		// Unenrolled: there is no org to tell; the local mark still holds.
		n, err = store.New(s.db()).MarkOrgMessageThreadRead(ctx, id, "", false, s.now())
	}
	switch {
	case errors.Is(err, store.ErrOrgMessageNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	if n > 0 {
		s.recordManageAudit(r, "messages_read", fmt.Sprintf("count=%d receipts=%t", n, receipts))
	}
	writeJSON(w, map[string]any{"marked": n, "read_receipts": receipts})
}

func (s *Server) handleMessageAck(w http.ResponseWriter, r *http.Request, rawID string) {
	if !requireConfirmToken(w, r) {
		return
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	svc := s.opts.Messages
	if svc == nil {
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "acknowledgements go to an organization; this machine is not enrolled")
		return
	}
	m, err := svc.AckOrgMessage(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrOrgMessageNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrOrgMessageAckNotRequested):
		messagesError(w, http.StatusConflict, "not_requested", "this message did not ask for an acknowledgement")
		return
	case errors.Is(err, orgclient.ErrNotEnrolled):
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "acknowledgements go to an organization; this machine is not enrolled")
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "messages_ack", "count=1")
	writeJSON(w, map[string]any{"message": m})
}

func (s *Server) handleMessageOutboxDiscard(w http.ResponseWriter, r *http.Request, id string) {
	if !requireConfirmToken(w, r) {
		return
	}
	if !messageIDOK(id) || s.db() == nil {
		http.NotFound(w, r)
		return
	}
	var (
		ok  bool
		err error
	)
	if svc := s.opts.Messages; svc != nil {
		ok, err = svc.DiscardOrgMessage(r.Context(), id)
	} else {
		ok, err = store.New(s.db()).DiscardOrgMessageOutbox(r.Context(), id)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.recordManageAudit(r, "messages_discard", "count=1")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMessageOutboxRetry(w http.ResponseWriter, r *http.Request, id string) {
	if !requireConfirmToken(w, r) {
		return
	}
	if !messageIDOK(id) {
		http.NotFound(w, r)
		return
	}
	svc := s.opts.Messages
	if svc == nil {
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "messages go to an organization; this machine is not enrolled")
		return
	}
	item, err := svc.RetryOrgMessage(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrOrgMessageNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, orgclient.ErrNotEnrolled):
		messagesError(w, http.StatusConflict, messagesRailNotEnrolled, "messages go to an organization; this machine is not enrolled")
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "messages_retry", "state="+item.State)
	writeJSON(w, map[string]any{"item": item})
}

// messagesPushView is what a push surface (VS Code, the nav badge) shows
// under the developer's alerts_only choice.
type messagesPushView struct {
	Unread int                     `json:"unread"`
	Newest *store.OrgMessageNewest `json:"newest"`
}

// messagesSummaryResponse is GET /api/messages/summary.
type messagesSummaryResponse struct {
	Enrolled bool             `json:"enrolled"`
	Rail     messagesRailView `json:"rail"`
	store.OrgMessageSummary
	Push     messagesPushView `json:"push"`
	Surfaces messagesSurfaces `json:"surfaces"`
}

// pushView applies alerts_only (the one place it is decided for VS Code and
// the nav badge).
func pushView(sum store.OrgMessageSummary, alertsOnly bool) messagesPushView {
	if alertsOnly {
		return messagesPushView{Unread: sum.UnreadAlerts, Newest: sum.NewestAlert}
	}
	return messagesPushView{Unread: sum.Unread, Newest: sum.Newest}
}

func (s *Server) handleMessagesSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	mc := s.messagesContext(ctx)
	out := messagesSummaryResponse{Enrolled: mc.enrolled, Rail: mc.railView(), Surfaces: surfacesOf(mc.cfg, mc.managed)}
	if s.db() != nil {
		sum, err := store.New(s.db()).OrgMessageSummary(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		out.OrgMessageSummary = sum
	}
	out.Push = pushView(out.OrgMessageSummary, mc.cfg.AlertsOnly)
	writeJSON(w, out)
}

// messageIDOK bounds an id taken from a URL path (thread ids and outbox
// client ids are UUIDs or short slugs).
func messageIDOK(id string) bool {
	return id != "" && len(id) <= 128 && prefillParamOK(id, 128)
}

// loadMessageNotifications is the bell's message source: conversations with
// unread admin messages, and the developer's posts that did not reach the
// org. alerts_only mutes non-alert conversations in the bell (a push
// surface); the Messages page itself always lists everything.
func (s *Server) loadMessageNotifications(r *http.Request, in *feed.Input) {
	if s.db() == nil {
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		in.OrgMessagesAlertsOnly = cfg.Messages.AlertsOnly
	}
	if threads, err := st.ListUnreadOrgMessageThreads(ctx, 50); err == nil {
		for _, t := range threads {
			in.OrgMessages = append(in.OrgMessages, feed.OrgMessageThread{
				ThreadID: t.ThreadID, Subject: t.Subject, Kind: t.Kind, NewestID: t.NewestID,
				NewestAuthor: t.NewestAuthor, NewestAt: parseStampLoose(t.NewestAt), Unread: t.Unread, NeedsAck: t.NeedsAck,
			})
		}
	}
	if posts, err := st.ListOrgMessageOutboxPosts(ctx); err == nil {
		for _, p := range posts {
			if p.State == store.OrgMessageOutboxSent {
				continue
			}
			at := parseStampLoose(p.LastAttemptAt)
			if at.IsZero() {
				at = parseStampLoose(p.CreatedAt)
			}
			in.OrgMessagesUnsent = append(in.OrgMessagesUnsent, feed.OrgMessageUnsent{
				ID: p.ClientMsgID, ThreadID: p.ThreadID, Subject: p.NewSubject,
				Failed: p.State == store.OrgMessageOutboxFailed, Attempts: p.Attempts, LastError: p.LastError, At: at,
			})
		}
	}
}
