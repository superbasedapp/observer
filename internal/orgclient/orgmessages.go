package orgclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin and developer messaging, node half
// (docs/plans/admin-developer-messaging-plan-2026-10-15.md sections 2, 3, 9
// and 17.6, T-854).
//
// SyncOrgMessages is the ONE seam: the push cycle calls it after the request
// outbox flush, and the policy-freshness checker calls it when the org's
// RailVersions["messages"] moves, so a new admin message usually reaches an
// active node in seconds. It never opens a port and never adds a host: it
// talks only to the org server this node is enrolled with, over the bearer
// and machine proof every other rail uses.
//
// One sync is two halves, in order:
//
//  1. FLUSH the outbox (replies, developer-started threads, read and
//     acknowledge receipts) with POST /api/agent/messages and
//     POST /api/agent/messages/receipts. Each post is idempotent on its
//     node-minted client_msg_id, so a retry after a lost response never
//     duplicates. A refusal on the merits (threads_disabled,
//     topic_not_allowed, thread_closed, not_found, a 400) keeps the row as
//     failed with the reason, honestly; everything else keeps it queued.
//  2. PULL GET /api/agent/messages?after=<cursor>, verify the org's
//     signature for (org, this member), refuse a lower version from the same
//     key (a replay), store each page atomically with its cursor, and page
//     until the org says there is no more.
//
// The ladder copies the budget rail (classifyBudgetResponse): an older server
// (404 / 405 / 501 / an HTML page) is not_supported, backs off
// (railbackoff.go) and keeps every held message; 304 keeps; 401/403 is
// auth_failed; 409 is channel_off (the org has no signer); anything else is
// unreachable. Nothing on this path ever deletes a held message: only a
// change of enrolment identity does (store.ClearIdentityBoundDocs).

// orgMessagesRail names the rail in the shared not-supported log line.
const orgMessagesRail = "org-messages"

// Fetch states recorded in org_message_rail.fetch_state (a closed set).
const (
	// MessagesFetchOK: the last pull verified (a page, or a 304).
	MessagesFetchOK = "ok"
	// MessagesFetchNotSupported: the org server predates messaging.
	MessagesFetchNotSupported = "not_supported"
	// MessagesFetchAuthFailed: the org refused this node's credential.
	MessagesFetchAuthFailed = "auth_failed"
	// MessagesFetchChannelOff: the org has no signing key configured.
	MessagesFetchChannelOff = "channel_off"
	// MessagesFetchUnreachable: transport failure or an unexpected status.
	MessagesFetchUnreachable = "unreachable"
	// MessagesFetchUnverified: a document arrived and was refused.
	MessagesFetchUnverified = "unverified"
)

// maxOrgMessagePages bounds one sync's pull. The org pages at 200 messages,
// so this is 10,000 messages; anything beyond continues next cycle.
const maxOrgMessagePages = 50

// maxOrgMessageDocBytes caps one pull page. A page holds at most
// OrgMessagePageSize messages of at most OrgMessageMaxBody bytes each, plus
// attachments and thread headers, which is well over the 1 MiB other rails
// use.
const maxOrgMessageDocBytes = 8 << 20

// maxOrgMessageReceiptsPerPost bounds one receipts POST.
const maxOrgMessageReceiptsPerPost = 200

// sendFlushTimeout bounds the immediate flush a developer action triggers,
// so the dashboard never waits on a slow org for long; anything not sent by
// then stays queued for the next cycle.
const sendFlushTimeout = 15 * time.Second

// desktopRecent bounds which new messages may raise a desktop notification:
// a node re-pulling its history (a fresh enrolment) must not pop one toast
// per old message.
const desktopRecent = 24 * time.Hour

// ErrOrgMessagesUnavailable is returned by developer actions when the org
// server does not serve messaging (an older server).
var ErrOrgMessagesUnavailable = errors.New("orgclient: the organization's server does not support messages yet")

// orgMessagesState is the rail's in-memory state (one owner: Client).
type orgMessagesState struct {
	// mu serializes a whole sync (flush then pull) so two triggers never
	// race the cursor or post the same row twice concurrently.
	mu sync.Mutex
	// notFound spaces out a server that does not serve the rail.
	notFound notFoundBackoff
	// settings reads the developer's [messages] section at use time; nil =
	// the defaults.
	settings func() config.MessagesConfig
	// sink receives the admin messages a pull newly stored.
	sink func([]OrgMessageNotice)
	// stalled is set when a flush or pull could not reach the org (or the
	// org refused this node's credential) and cleared by the next clean
	// sync. While it is set, any other request the org answers (a push, a
	// policy-version probe) retries the rail at once instead of leaving a
	// queued reply waiting for the next full cycle (T-854 bug 1).
	stalled atomic.Bool
	// retrying keeps the stall retry to one at a time.
	retrying atomic.Bool
}

// OrgMessageNotice is what a push surface outside the dashboard (the OS
// desktop notification) may say about one new admin message: who wrote it
// and the conversation's subject, never the body.
type OrgMessageNotice struct {
	ThreadID   string
	MessageID  int64
	Subject    string
	AuthorName string
	// Kind is the conversation's kind (note | coaching | alert).
	Kind string
}

// SetMessagesSettings installs the reader of the developer's [messages]
// section. It is read each time it matters (a read receipt, a new message),
// so a change applies without a restart. Nil-safe.
func (c *Client) SetMessagesSettings(fn func() config.MessagesConfig) {
	if c == nil {
		return
	}
	c.messages.settings = fn
}

// SetOrgMessageSink installs the callback that receives the admin messages
// each pull newly stored (the desktop notification, wired in cmd/observer).
// It is called after the pull, outside any lock, at most once per message.
// Nil-safe.
func (c *Client) SetOrgMessageSink(fn func([]OrgMessageNotice)) {
	if c == nil {
		return
	}
	c.messages.sink = fn
}

func (c *Client) messagesSettings() config.MessagesConfig {
	if c.messages.settings != nil {
		return c.messages.settings()
	}
	return config.DefaultMessagesConfig()
}

// OrgMessagesSyncResult reports one sync.
type OrgMessagesSyncResult struct {
	// Sent / Failed count outbox rows the org accepted or refused.
	Sent, Failed int
	// Received counts messages the pull newly stored (both authors).
	Received int
	// State is the pull's fetch state (MessagesFetch*), "" when no pull ran.
	State string
}

// SyncOrgMessages flushes the outbox and then pulls new messages. It is the
// one entry point the push cycle and the freshness checker call.
func (c *Client) SyncOrgMessages(ctx context.Context) (OrgMessagesSyncResult, error) {
	if c == nil {
		return OrgMessagesSyncResult{}, ErrNotEnrolled
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return OrgMessagesSyncResult{}, fmt.Errorf("orgclient.SyncOrgMessages: enrolment: %w", err)
	}
	if enr == nil {
		return OrgMessagesSyncResult{}, ErrNotEnrolled
	}
	// A server that does not serve the rail is re-asked on a doubling
	// interval; skipping changes nothing (a 404 never clears anything).
	if c.messages.notFound.Skip(time.Now()) {
		return OrgMessagesSyncResult{State: MessagesFetchNotSupported}, nil
	}
	c.messages.mu.Lock()
	sent, failed, ferr := c.flushOrgMessageOutbox(ctx, enr)
	res := OrgMessagesSyncResult{Sent: sent, Failed: failed}
	inserted, state, perr := c.pullOrgMessages(ctx, enr)
	c.messages.mu.Unlock()
	res.Received, res.State = len(inserted), state
	c.deliverToSink(ctx, inserted)
	switch {
	case ferr == nil && perr == nil:
		c.messages.stalled.Store(false)
	case perr != nil && stallStates[state]:
		c.messages.stalled.Store(true)
	}
	if perr != nil {
		return res, perr
	}
	return res, ferr
}

// stallStates are the pull outcomes a later successful request to the same
// org can cure: the org was unreachable or refused the credential. A
// refused document (unverified) or a channel the org switched off is not
// retried early; the next regular cycle asks again.
var stallStates = map[string]bool{
	MessagesFetchUnreachable: true,
	MessagesFetchAuthFailed:  true,
}

// retryStalledOrgMessages runs one sync right away when the message rail is
// stalled, called after the org has just answered another request from this
// node (a push, a policy-version probe). Without it a reply queued while the
// org was down waited for the next full push cycle, which after a long
// outage is the push loop's backed-off interval (minutes). The rail counts
// as stalled when its last sync failed or the outbox still holds queued
// rows (a daemon restarted during the outage). It runs at most one retry at
// a time, bounded like a developer's send, and reports whether it ran.
func (c *Client) retryStalledOrgMessages(ctx context.Context) bool {
	if c == nil || !c.orgMessagesStalled(ctx) {
		return false
	}
	if !c.messages.retrying.CompareAndSwap(false, true) {
		return false
	}
	defer c.messages.retrying.Store(false)
	fctx, cancel := context.WithTimeout(ctx, sendFlushTimeout)
	defer cancel()
	res, err := c.SyncOrgMessages(fctx)
	if err == nil && (res.Sent > 0 || res.Received > 0) && c.logger != nil {
		c.logger.Info("org messages caught up after the org came back", "sent", res.Sent, "received", res.Received)
	}
	return true
}

// orgMessagesStalled reports whether the rail needs an early retry.
func (c *Client) orgMessagesStalled(ctx context.Context) bool {
	if c.messages.stalled.Load() {
		return true
	}
	if c.store == nil || c.messages.notFound.Skip(time.Now()) {
		return false
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return false
	}
	pending, err := c.store.PendingOrgMessageOutbox(ctx, enr.OrgID)
	return err == nil && len(pending) > 0
}

// syncOrgMessagesInCycle is the push cycle's call: one sync, its failure
// logged once per kind and never affecting push health.
func (c *Client) syncOrgMessagesInCycle(ctx context.Context, d *failureDeduper) {
	if _, err := c.SyncOrgMessages(ctx); err != nil && !errors.Is(err, ErrNotEnrolled) && !errors.Is(err, context.Canceled) {
		warnOnce(c.logger, d, err,
			"org messages could not be synced - held messages stay readable and unsent replies stay queued; if this persists, check the org server")
		return
	}
	d.observe("")
}

// deliverToSink hands the newly stored, recent ADMIN messages to the sink,
// each with its conversation's subject and kind.
func (c *Client) deliverToSink(ctx context.Context, inserted []store.OrgInboxMessage) {
	if c.messages.sink == nil || len(inserted) == 0 {
		return
	}
	now := time.Now()
	var notices []OrgMessageNotice
	for _, m := range inserted {
		if m.AuthorKind != orgcontract.OrgMessageAuthorAdmin {
			continue
		}
		if at, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err == nil && now.Sub(at) > desktopRecent {
			continue
		}
		n := OrgMessageNotice{ThreadID: m.ThreadID, MessageID: m.ID, AuthorName: m.AuthorName, Kind: orgcontract.OrgMessageKindNote}
		if subject, kind, ok, err := c.store.OrgMessageThreadHeader(ctx, m.ThreadID); err == nil && ok {
			n.Subject, n.Kind = subject, kind
		}
		notices = append(notices, n)
	}
	if len(notices) > 0 {
		c.messages.sink(notices)
	}
}

// --- flush ------------------------------------------------------------------

// postVerdict is what one outbox POST answer means for the row.
type postVerdict int

const (
	// postAccepted: the org stored it.
	postAccepted postVerdict = iota
	// postRefused: refused on its merits; the row is kept as failed.
	postRefused
	// postRetry: not this row's fault; keep it queued and stop the flush
	// (the next row would meet the same answer).
	postRetry
)

// postAnswer classifies one answer. code is the JSON {"error": code} the
// server sent, "" when none.
type postAnswer struct {
	verdict postVerdict
	// state is the rail state this answer implies for a retry (it is what
	// the outbox row's last_error names, honestly).
	state string
}

// orgMessageRefusalCodes are the named refusals the org answers a post with
// (orgcontract.OrgMessageErr*). Any of them means "this message, as written,
// will not be accepted", whatever the status.
var orgMessageRefusalCodes = map[string]bool{
	orgcontract.OrgMessageErrThreadsDisabled: true,
	orgcontract.OrgMessageErrTopicNotAllowed: true,
	orgcontract.OrgMessageErrThreadClosed:    true,
	orgcontract.OrgMessageErrNotFound:        true,
}

// postAnswerRules is THE table (CLAUDE.md #5), walked top-down: the first
// row whose match holds decides. One test case per row.
var postAnswerRules = []struct {
	name   string
	match  func(status int, code string) bool
	answer postAnswer
}{
	{
		"accepted", func(s int, _ string) bool { return s == http.StatusOK || s == http.StatusCreated },
		postAnswer{postAccepted, MessagesFetchOK},
	},
	{
		"named refusal", func(_ int, code string) bool { return orgMessageRefusalCodes[code] },
		postAnswer{postRefused, ""},
	},
	// A 409 with no named code is the GET ladder's channel_off, not a
	// refusal of this message.
	{
		"channel off", func(s int, _ string) bool { return s == http.StatusConflict },
		postAnswer{postRetry, MessagesFetchChannelOff},
	},
	{
		"refused on its merits", func(s int, _ string) bool { return refusedStatuses[s] },
		postAnswer{postRefused, ""},
	},
	{
		"auth", func(s int, _ string) bool { return s == http.StatusUnauthorized || s == http.StatusForbidden },
		postAnswer{postRetry, MessagesFetchAuthFailed},
	},
	{
		"not served", func(s int, _ string) bool { return railNotSupportedStatuses[s] },
		postAnswer{postRetry, MessagesFetchNotSupported},
	},
	{
		"anything else", func(int, string) bool { return true },
		postAnswer{postRetry, MessagesFetchUnreachable},
	},
}

func classifyPostAnswer(status int, code string) postAnswer {
	for _, r := range postAnswerRules {
		if r.match(status, code) {
			return r.answer
		}
	}
	return postAnswer{postRetry, MessagesFetchUnreachable}
}

// retryText is the developer-facing reason a queued row is still waiting.
var retryText = map[string]string{
	MessagesFetchChannelOff:   "your organization's message channel is off; it is retried automatically",
	MessagesFetchAuthFailed:   "your organization refused this machine's credential; it is retried automatically",
	MessagesFetchNotSupported: "your organization's server does not support messages yet",
	MessagesFetchUnreachable:  "your organization could not be reached; it is retried automatically",
}

// refusalText is the developer-facing reason for a named refusal.
var refusalText = map[string]string{
	orgcontract.OrgMessageErrThreadsDisabled: "your organization does not let you start conversations",
	orgcontract.OrgMessageErrTopicNotAllowed: "your organization does not take messages on this topic",
	orgcontract.OrgMessageErrThreadClosed:    "this conversation was closed by your admin",
	orgcontract.OrgMessageErrNotFound:        "this conversation no longer exists",
}

// flushOrgMessageOutbox sends every queued row for the current org, posts
// first (oldest first), then the receipts in batches. It stops at the first
// answer that is not this row's fault.
func (c *Client) flushOrgMessageOutbox(ctx context.Context, enr *store.Enrolment) (sent, failed int, err error) {
	pending, err := c.store.PendingOrgMessageOutbox(ctx, enr.OrgID)
	if err != nil {
		return 0, 0, err
	}
	var receipts []store.OrgMessageOutboxItem
	for _, item := range pending {
		if item.Kind == store.OrgMessageOutboxReceipt {
			receipts = append(receipts, item)
			continue
		}
		post := orgcontract.OrgMessagePost{
			ClientMsgID: item.ClientMsgID, ThreadID: item.ThreadID, Body: item.Body, Attachments: item.Attachments,
		}
		if item.ThreadID == "" {
			post.NewThread = &orgcontract.OrgMessageNewThread{Subject: item.NewSubject, Topic: item.NewTopic}
		}
		var result orgcontract.OrgMessagePostResult
		ans, code, perr := c.postOrgMessageJSON(ctx, enr, orgcontract.OrgMessagesPath, post, &result)
		now := time.Now()
		switch ans.verdict {
		case postAccepted:
			if err := c.store.MarkOrgMessageOutboxSent(ctx, item.ClientMsgID, result.MessageID, result.ThreadID, now); err != nil {
				return sent, failed, err
			}
			sent++
		case postRefused:
			_ = c.store.NoteOrgMessageOutboxAttempt(ctx, item.ClientMsgID, refusalReason(code, perr), code, true, now)
			failed++
		default:
			_ = c.store.NoteOrgMessageOutboxAttempt(ctx, item.ClientMsgID, retryReason(ans.state, perr), "", false, now)
			return sent, failed, c.flushStop(ans.state, perr)
		}
	}
	for start := 0; start < len(receipts); start += maxOrgMessageReceiptsPerPost {
		end := start + maxOrgMessageReceiptsPerPost
		if end > len(receipts) {
			end = len(receipts)
		}
		batch := receipts[start:end]
		body := orgcontract.OrgMessageReceipts{Receipts: make([]orgcontract.OrgMessageReceipt, 0, len(batch))}
		for _, r := range batch {
			body.Receipts = append(body.Receipts, orgcontract.OrgMessageReceipt{
				MessageID: r.ReceiptMessageID, State: r.ReceiptState, At: r.ReceiptAt,
			})
		}
		ans, code, perr := c.postOrgMessageJSON(ctx, enr, orgcontract.OrgMessageReceiptsPath, body, nil)
		now := time.Now()
		for _, r := range batch {
			switch ans.verdict {
			case postAccepted:
				if err := c.store.MarkOrgMessageOutboxSent(ctx, r.ClientMsgID, 0, "", now); err != nil {
					return sent, failed, err
				}
				sent++
			case postRefused:
				_ = c.store.NoteOrgMessageOutboxAttempt(ctx, r.ClientMsgID, refusalReason(code, perr), code, true, now)
				failed++
			default:
				_ = c.store.NoteOrgMessageOutboxAttempt(ctx, r.ClientMsgID, retryReason(ans.state, perr), "", false, now)
			}
		}
		if ans.verdict == postRetry {
			return sent, failed, c.flushStop(ans.state, perr)
		}
	}
	return sent, failed, nil
}

func refusalReason(code string, perr error) string {
	if t, ok := refusalText[code]; ok {
		return t
	}
	if perr != nil {
		return "your organization refused this message: " + perr.Error()
	}
	return "your organization refused this message"
}

func retryReason(state string, perr error) string {
	if t, ok := retryText[state]; ok {
		return t
	}
	if perr != nil {
		return perr.Error()
	}
	return retryText[MessagesFetchUnreachable]
}

// flushStop is flushStopErr plus the stall mark: a flush that stopped for
// any reason but an older server leaves queued rows behind, so the rail is
// stalled until a clean sync.
func (c *Client) flushStop(state string, perr error) error {
	err := flushStopErr(state, perr)
	if err != nil {
		c.messages.stalled.Store(true)
	}
	return err
}

func flushStopErr(state string, perr error) error {
	if state == MessagesFetchNotSupported {
		return nil // an older server: honest, quiet, the pull reports it
	}
	if perr != nil {
		return fmt.Errorf("orgclient.SyncOrgMessages: flush: %w", perr)
	}
	return fmt.Errorf("orgclient.SyncOrgMessages: flush: %s", state)
}

// postOrgMessageJSON POSTs v to path with the bearer and, on a managed
// node, the machine proof. It returns the classified answer, the refusal
// code the server named (if any) and, for a non-2xx answer or a transport
// failure, an error describing it. out (when non-nil) receives a 2xx body.
func (c *Client) postOrgMessageJSON(ctx context.Context, enr *store.Enrolment, path string, v, out any) (postAnswer, string, error) {
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return postAnswer{postRetry, MessagesFetchAuthFailed}, "", fmt.Errorf("bearer: %w", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return postAnswer{postRefused, ""}, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(enr.OrgServerURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return postAnswer{postRetry, MessagesFetchUnreachable}, "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	if machine := orgcontract.SanitizeMachineHeader(c.ManagedMachineIdentity(ctx)); machine != "" {
		req.Header.Set(orgcontract.HeaderMachineIdentity, machine)
		c.attachMachineProof(ctx, req, enr, machine, http.MethodPost, path)
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return postAnswer{postRetry, MessagesFetchUnreachable}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxOrgRequestResponseBytes))
	var named struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &named)
	ans := classifyPostAnswer(resp.StatusCode, named.Error)
	if ans.verdict == postAccepted {
		if out != nil {
			if err := json.Unmarshal(body, out); err != nil {
				// The org stored it (2xx); a body we cannot read only loses the
				// result ids, which the pull brings back anyway.
				c.logger.Debug("org message post: unreadable 2xx body", "err", err)
			}
		}
		return ans, "", nil
	}
	detail := strings.TrimSpace(firstNonBlank(named.Message, named.Error))
	if detail == "" {
		detail = "server returned " + strconv.Itoa(resp.StatusCode)
	}
	return ans, named.Error, errors.New(detail)
}

// --- pull -------------------------------------------------------------------

// pullOrgMessages pages the signed pull until More is false. It returns the
// messages it newly stored and the final fetch state.
func (c *Client) pullOrgMessages(ctx context.Context, enr *store.Enrolment) ([]store.OrgInboxMessage, string, error) {
	var inserted []store.OrgInboxMessage
	var policy orgcontract.OrgMessageNodePolicy
	havePolicy := false
	for page := 0; page < maxOrgMessagePages; page++ {
		done, got, pol, state, err := c.pullOrgMessagePage(ctx, enr)
		inserted = append(inserted, got...)
		if pol != nil {
			policy, havePolicy = *pol, true
		}
		if err != nil || state != MessagesFetchOK {
			if nerr := c.store.NoteOrgMessageFetch(ctx, state, errText(err), time.Now()); nerr != nil {
				c.logger.Debug("org messages: recording the fetch state failed", "err", nerr)
			}
			return inserted, state, err
		}
		if done {
			break
		}
	}
	if havePolicy {
		if _, err := c.store.PruneOrgMessages(ctx, policy.RetentionDays, time.Now()); err != nil {
			c.logger.Debug("org messages: local prune failed", "err", err)
		}
	}
	return inserted, MessagesFetchOK, nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// pullOrgMessagePage fetches and stores one page. done reports the last
// page (More=false, a 304, or a page that did not advance).
func (c *Client) pullOrgMessagePage(ctx context.Context, enr *store.Enrolment) (done bool, inserted []store.OrgInboxMessage, policy *orgcontract.OrgMessageNodePolicy, state string, err error) {
	rail, have, err := c.store.LoadOrgMessageRail(ctx)
	if err != nil {
		return true, nil, nil, MessagesFetchUnreachable, err
	}
	sameIdentity := have && rail.OrgID == enr.OrgID && rail.Subject == enr.UserID
	cursor, etag := int64(0), ""
	if sameIdentity {
		cursor, etag = rail.Cursor, rail.ETag
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return true, nil, nil, MessagesFetchAuthFailed, fmt.Errorf("orgclient.SyncOrgMessages: bearer: %w", err)
	}
	u := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.OrgMessagesPath + "?after=" + url.QueryEscape(strconv.FormatInt(cursor, 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return true, nil, nil, MessagesFetchUnreachable, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if machine := orgcontract.SanitizeMachineHeader(c.ManagedMachineIdentity(ctx)); machine != "" {
		req.Header.Set(orgcontract.HeaderMachineIdentity, machine)
		c.attachMachineProof(ctx, req, enr, machine, http.MethodGet, orgcontract.OrgMessagesPath)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return true, nil, nil, MessagesFetchUnreachable, fmt.Errorf("orgclient.SyncOrgMessages: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	notServed := c.classifyRail(orgMessagesRail, resp) == railReplyNotSupported
	c.messages.notFound.Observe(notServed, time.Now(), c.pushInterval())
	switch {
	case notServed:
		// An older server: keep everything held, report it, back off.
		return true, nil, nil, MessagesFetchNotSupported, nil
	case resp.StatusCode == http.StatusNotModified:
		if etag == "" {
			return true, nil, nil, MessagesFetchUnverified, errors.New("orgclient.SyncOrgMessages: 304 without a validator this node sent")
		}
		return true, nil, nil, MessagesFetchOK, c.store.NoteOrgMessageFetch(ctx, MessagesFetchOK, "", time.Now())
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return true, nil, nil, MessagesFetchAuthFailed, fmt.Errorf("orgclient.SyncOrgMessages: server returned %d", resp.StatusCode)
	case resp.StatusCode == http.StatusConflict:
		return true, nil, nil, MessagesFetchChannelOff, errors.New("orgclient.SyncOrgMessages: message channel off (409)")
	case resp.StatusCode != http.StatusOK:
		return true, nil, nil, MessagesFetchUnreachable, fmt.Errorf("orgclient.SyncOrgMessages: server returned %d", resp.StatusCode)
	}

	var held *store.OrgMessageRail
	if sameIdentity {
		held = &rail
	}
	doc, fingerprint, err := c.verifyOrgMessagePage(ctx, resp, enr, cursor, held)
	if err != nil {
		return true, nil, nil, MessagesFetchUnverified, err
	}
	pageETag := ""
	if !doc.More {
		pageETag = strings.TrimSpace(resp.Header.Get("ETag"))
	}
	res, err := c.store.SaveOrgMessagePage(ctx, store.OrgMessagePage{
		OrgID: enr.OrgID, Subject: enr.UserID, Body: doc.OrgMessageBody, ExpectCursor: cursor,
		ETag: pageETag, KeyFingerprint: fingerprint, Now: time.Now(),
	})
	if errors.Is(err, store.ErrOrgMessageCursorMoved) {
		// Another writer moved on; nothing is lost, the next sync continues.
		return true, nil, &doc.Policy, MessagesFetchOK, nil
	}
	if err != nil {
		return true, nil, nil, MessagesFetchUnreachable, fmt.Errorf("orgclient.SyncOrgMessages: store: %w", err)
	}
	if len(res.Inserted) > 0 {
		c.logger.Info("org messages stored", "count", len(res.Inserted), "cursor", res.Cursor)
	}
	done = !doc.More || res.Cursor <= cursor
	return done, res.Inserted, &doc.Policy, MessagesFetchOK, nil
}

// verifyOrgMessagePage decodes one 200 page and refuses it unless it
// verifies for (org, this member) under the pinned org key, answers the
// cursor that was asked for, does not lower the version the same key
// already gave (a replay; held is nil when nothing is held for this
// identity), and carries only messages above the cursor. It returns the
// document and the verifying key's fingerprint.
func (c *Client) verifyOrgMessagePage(ctx context.Context, resp *http.Response, enr *store.Enrolment, cursor int64, held *store.OrgMessageRail) (orgcontract.OrgMessageDoc, string, error) {
	var doc orgcontract.OrgMessageDoc
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgMessageDocBytes, &doc); err != nil {
		return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: decode: %w", err)
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: %w", err)
	}
	// The signature binds (org, subject): a genuine document minted for
	// another member does not verify here, whatever its body says.
	if err := orgcontract.VerifyOrgMessages(pub, enr.OrgID, enr.UserID, doc); err != nil {
		return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: %w", err)
	}
	if doc.After != cursor {
		return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: refusing a page for cursor %d, asked for %d", doc.After, cursor)
	}
	fingerprint := orgcontract.PublicKeyPinHash(pub)
	if held != nil && held.KeyFingerprint == fingerprint && doc.Version < held.Version {
		return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: refusing message version %d, older than the held %d (replay)", doc.Version, held.Version)
	}
	for _, m := range doc.Messages {
		if m.ID <= cursor {
			return doc, "", fmt.Errorf("orgclient.SyncOrgMessages: refusing message %d at or below the cursor %d", m.ID, cursor)
		}
	}
	return doc, fingerprint, nil
}

// --- developer actions --------------------------------------------------------

// OrgMessageDraft is what the developer wrote in the dashboard: a reply
// (ThreadID) or a new thread (Subject + Topic).
type OrgMessageDraft struct {
	ClientMsgID string                             `json:"client_msg_id,omitempty"`
	ThreadID    string                             `json:"thread_id,omitempty"`
	Subject     string                             `json:"subject,omitempty"`
	Topic       string                             `json:"topic,omitempty"`
	Body        string                             `json:"body"`
	Attachments []orgcontract.OrgMessageAttachment `json:"attachments,omitempty"`
}

// SendOrgMessage writes the draft into the outbox, then tries to send it at
// once (bounded by sendFlushTimeout) and pulls, so the reply shows in the
// thread right away when the org is reachable. The returned item says what
// happened: queued (it waits for the next cycle), sent, or failed (refused,
// with the reason). A missing ClientMsgID is minted here; passing one makes
// a double-submitted form idempotent.
func (c *Client) SendOrgMessage(ctx context.Context, d OrgMessageDraft) (store.OrgMessageOutboxItem, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return store.OrgMessageOutboxItem{}, fmt.Errorf("orgclient.SendOrgMessage: enrolment: %w", err)
	}
	if enr == nil {
		return store.OrgMessageOutboxItem{}, ErrNotEnrolled
	}
	if rail, ok, _ := c.store.LoadOrgMessageRail(ctx); ok && rail.FetchState == MessagesFetchNotSupported {
		return store.OrgMessageOutboxItem{}, ErrOrgMessagesUnavailable
	}
	id := strings.TrimSpace(d.ClientMsgID)
	if id == "" {
		id = uuid.NewString()
	}
	item, err := c.store.EnqueueOrgMessagePost(ctx, store.OrgMessagePostDraft{
		ClientMsgID: id, OrgID: enr.OrgID, ThreadID: d.ThreadID, NewSubject: d.Subject, NewTopic: d.Topic,
		Body: d.Body, Attachments: d.Attachments, Now: time.Now(),
	})
	if err != nil {
		return store.OrgMessageOutboxItem{}, err
	}
	return c.flushThenReport(ctx, enr, item)
}

// RetryOrgMessage moves a failed post back to the queue and sends it now.
func (c *Client) RetryOrgMessage(ctx context.Context, id string) (store.OrgMessageOutboxItem, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		if err == nil {
			err = ErrNotEnrolled
		}
		return store.OrgMessageOutboxItem{}, err
	}
	item, ok, err := c.store.GetOrgMessageOutboxItem(ctx, id)
	if err != nil {
		return store.OrgMessageOutboxItem{}, err
	}
	if !ok {
		return store.OrgMessageOutboxItem{}, store.ErrOrgMessageNotFound
	}
	if _, err := c.store.RequeueOrgMessageOutbox(ctx, id); err != nil {
		return store.OrgMessageOutboxItem{}, err
	}
	item.State = store.OrgMessageOutboxQueued
	return c.flushThenReport(ctx, enr, item)
}

// flushThenReport runs one bounded flush, reads the row back (its state is
// the answer), then pulls so an accepted message comes back as stored.
func (c *Client) flushThenReport(ctx context.Context, enr *store.Enrolment, item store.OrgMessageOutboxItem) (store.OrgMessageOutboxItem, error) {
	fctx, cancel := context.WithTimeout(ctx, sendFlushTimeout)
	defer cancel()
	if !c.messages.notFound.Skip(time.Now()) {
		c.messages.mu.Lock()
		_, _, _ = c.flushOrgMessageOutbox(fctx, enr)
		c.messages.mu.Unlock()
	}
	if cur, ok, err := c.store.GetOrgMessageOutboxItem(ctx, item.ClientMsgID); err == nil && ok {
		item = cur
	}
	if item.State == store.OrgMessageOutboxSent {
		// Bring the stored copy back now; failures leave the sent row, which
		// the page renders until the next pull.
		_, _ = c.SyncOrgMessages(fctx)
	}
	return item, nil
}

// OrgMessageReadReceiptsOn reports whether this node tells the org when the
// developer reads a message: always on a managed enrolment (the enterprise
// full-capture ruling), the developer's [messages].read_receipts on an
// individual one. Acknowledgements are always reported.
func (c *Client) OrgMessageReadReceiptsOn(ctx context.Context) bool {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return false
	}
	managed, merr := NodeManagedFor(ctx, c.store, enr) // P-204: switched nodes too
	return readReceiptsOn(merr == nil && managed, c.messagesSettings().ReadReceipts)
}

// readReceiptsOn is the one rule (plan section 9): managed always, else the
// developer's choice.
func readReceiptsOn(managed, localChoice bool) bool {
	return managed || localChoice
}

// MarkOrgMessageThreadRead marks a thread read on this machine and, when
// read receipts are on, queues and sends the receipts.
func (c *Client) MarkOrgMessageThreadRead(ctx context.Context, threadID string) (int, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return 0, err
	}
	orgID, receipts := "", false
	if enr != nil {
		managed, merr := NodeManagedFor(ctx, c.store, enr) // P-204: switched nodes too
		orgID, receipts = enr.OrgID, readReceiptsOn(merr == nil && managed, c.messagesSettings().ReadReceipts)
	}
	n, err := c.store.MarkOrgMessageThreadRead(ctx, threadID, orgID, receipts && orgID != "", time.Now())
	if err != nil || n == 0 || !receipts || enr == nil {
		return n, err
	}
	c.flushQuietly(ctx, enr)
	return n, nil
}

// AckOrgMessage acknowledges one admin message and sends the receipt.
func (c *Client) AckOrgMessage(ctx context.Context, id int64) (store.OrgInboxMessage, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return store.OrgInboxMessage{}, err
	}
	if enr == nil {
		return store.OrgInboxMessage{}, ErrNotEnrolled
	}
	m, err := c.store.AckOrgMessage(ctx, id, enr.OrgID, time.Now())
	if err != nil {
		return m, err
	}
	c.flushQuietly(ctx, enr)
	return m, nil
}

// DiscardOrgMessage removes an outbox post the org has not accepted.
func (c *Client) DiscardOrgMessage(ctx context.Context, id string) (bool, error) {
	return c.store.DiscardOrgMessageOutbox(ctx, id)
}

// flushQuietly sends queued receipts now, bounded; a failure leaves them
// queued for the next cycle.
func (c *Client) flushQuietly(ctx context.Context, enr *store.Enrolment) {
	if c.messages.notFound.Skip(time.Now()) {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, sendFlushTimeout)
	defer cancel()
	c.messages.mu.Lock()
	defer c.messages.mu.Unlock()
	if _, _, err := c.flushOrgMessageOutbox(fctx, enr); err != nil {
		c.logger.Debug("org message receipts stay queued", "err", err)
	}
}
