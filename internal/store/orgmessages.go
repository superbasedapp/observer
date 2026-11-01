package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Admin and developer messaging, node half (agent migrations 173 to 176;
// docs/plans/admin-developer-messaging-plan-2026-10-15.md sections 6.2 and
// 17.6, T-854).
//
// ONE OWNER: org_message_rail, org_message_threads_local, org_messages_inbox
// and org_message_outbox are written exclusively here. NODE-LOCAL: received
// state and the developer's own unsent words, never pushed (privacy
// sentinel). The inbox writer (SaveOrgMessagePage) is reachable only from
// the verified-200 branch of orgclient's message pull: a 304, a 404, an
// unsigned or refused document never reaches it, and nothing on the pull
// path ever deletes a held message.

// Outbox kinds and states (the CHECK constraints of migration 176).
const (
	// OrgMessageOutboxPost is a reply or a developer-started thread.
	OrgMessageOutboxPost = "post"
	// OrgMessageOutboxReceipt is a read or acknowledged mark.
	OrgMessageOutboxReceipt = "receipt"

	// OrgMessageOutboxQueued waits for the next flush.
	OrgMessageOutboxQueued = "queued"
	// OrgMessageOutboxSent was accepted by the org; a post row stays until
	// the pull brings the stored message back.
	OrgMessageOutboxSent = "sent"
	// OrgMessageOutboxFailed was refused on its merits; kept with the reason
	// until the developer retries or discards it.
	OrgMessageOutboxFailed = "failed"
)

// MaxOrgMessageOutboxPosts bounds the unsent posts (queued plus failed) a
// node holds, so an org that is unreachable for weeks cannot grow the table
// without bound. Receipts are not counted: there is at most two per message.
const MaxOrgMessageOutboxPosts = 50

// DefaultOrgMessageLocalRetentionDays is the local cap on a closed thread
// when the org's policy names none (the feedstate precedent).
const DefaultOrgMessageLocalRetentionDays = 90

// sentPostKeep bounds how long a sent post waits for the pull to bring its
// stored copy back before the row is pruned anyway.
const sentPostKeep = 30 * 24 * time.Hour

// Errors.
var (
	// ErrOrgMessageOutboxFull is returned when MaxOrgMessageOutboxPosts
	// unsent posts are already queued.
	ErrOrgMessageOutboxFull = errors.New("store: message outbox is full")
	// ErrOrgMessageNotFound is returned for an unknown message or thread.
	ErrOrgMessageNotFound = errors.New("store: no such message")
	// ErrOrgMessageAckNotRequested is returned when acknowledging a message
	// the admin did not ask to be acknowledged.
	ErrOrgMessageAckNotRequested = errors.New("store: this message did not ask for an acknowledgement")
	// ErrOrgMessageCursorMoved is returned when a page was fetched for a
	// cursor another writer has since advanced; the page is discarded and
	// the next pull continues from the newer cursor.
	ErrOrgMessageCursorMoved = errors.New("store: message cursor moved during the pull")
	// ErrOrgMessageInvalid is wrapped by every post validation failure.
	ErrOrgMessageInvalid = errors.New("store: invalid message")
)

// OrgMessageRail is the single-row pull state.
type OrgMessageRail struct {
	OrgID          string
	Subject        string
	Cursor         int64
	Version        int64
	ETag           string
	KeyFingerprint string
	// Policy is the developer-facing policy of the last verified page;
	// HavePolicy is false until one arrived.
	Policy        orgcontract.OrgMessageNodePolicy
	HavePolicy    bool
	FetchState    string
	LastError     string
	LastAttemptAt string
	LastOKAt      string
}

// LoadOrgMessageRail returns the pull state; ok=false when this node never
// attempted a message pull.
func (s *Store) LoadOrgMessageRail(ctx context.Context) (OrgMessageRail, bool, error) {
	return loadOrgMessageRail(ctx, s.db)
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadOrgMessageRail(ctx context.Context, q rowQuerier) (OrgMessageRail, bool, error) {
	var r OrgMessageRail
	var policy string
	err := q.QueryRowContext(ctx, `
		SELECT org_id, subject, cursor, version, etag, key_fingerprint, policy_json,
		       fetch_state, last_error, last_attempt_at, last_ok_at
		  FROM org_message_rail WHERE id = 1`).
		Scan(&r.OrgID, &r.Subject, &r.Cursor, &r.Version, &r.ETag, &r.KeyFingerprint, &policy,
			&r.FetchState, &r.LastError, &r.LastAttemptAt, &r.LastOKAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgMessageRail{}, false, nil
	}
	if err != nil {
		return OrgMessageRail{}, false, fmt.Errorf("store.LoadOrgMessageRail: %w", err)
	}
	if strings.TrimSpace(policy) != "" {
		if err := json.Unmarshal([]byte(policy), &r.Policy); err == nil {
			r.HavePolicy = true
		}
	}
	return r, true, nil
}

// NoteOrgMessageFetch records the outcome of a pull attempt that stored no
// page (a 304, a refusal, an outage). It never touches the cursor or the
// held messages. state "ok" (a 304) also stamps last_ok_at.
func (s *Store) NoteOrgMessageFetch(ctx context.Context, state, errText string, now time.Time) error {
	stamp := stampTime(now)
	okAt := ""
	if state == "ok" {
		okAt = stamp
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO org_message_rail (id, fetch_state, last_error, last_attempt_at, last_ok_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		    fetch_state = excluded.fetch_state,
		    last_error = excluded.last_error,
		    last_attempt_at = excluded.last_attempt_at,
		    last_ok_at = CASE WHEN excluded.last_ok_at <> '' THEN excluded.last_ok_at ELSE org_message_rail.last_ok_at END`,
		state, boundText(errText, 500), stamp, okAt); err != nil {
		return fmt.Errorf("store.NoteOrgMessageFetch: %w", err)
	}
	return nil
}

// OrgMessagePage is one VERIFIED pull page to store.
type OrgMessagePage struct {
	OrgID   string
	Subject string
	Body    orgcontract.OrgMessageBody
	// ExpectCursor is the cursor the page was requested for (body.After).
	ExpectCursor int64
	// ETag is stored only for a final page (More=false); "" otherwise.
	ETag           string
	KeyFingerprint string
	Now            time.Time
}

// OrgMessagePageResult reports what one stored page changed.
type OrgMessagePageResult struct {
	// Inserted are the messages this page added (both authors), in id order.
	Inserted []OrgInboxMessage
	// Cursor is the cursor after the page.
	Cursor int64
}

// SaveOrgMessagePage stores one verified page atomically with the cursor:
// the thread headers, the new messages (a message already held is left
// exactly as it is, read and acknowledged marks included), the cursor, the
// version, the policy and the fetch state. A sent post whose stored copy
// arrived is dropped from the outbox in the same transaction.
//
// It refuses a page requested for a cursor another writer has since
// advanced (ErrOrgMessageCursorMoved): the rows would be harmless (ids are
// idempotent) but the cursor must never move backwards.
func (s *Store) SaveOrgMessagePage(ctx context.Context, p OrgMessagePage) (OrgMessagePageResult, error) {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	stamp := stampTime(now)
	policyRaw, err := json.Marshal(p.Body.Policy)
	if err != nil {
		return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: policy: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, have, err := loadOrgMessageRail(ctx, tx)
	if err != nil {
		return OrgMessagePageResult{}, err
	}
	sameIdentity := have && cur.OrgID == p.OrgID && cur.Subject == p.Subject
	current := int64(0)
	if sameIdentity {
		current = cur.Cursor
	}
	if current != p.ExpectCursor {
		return OrgMessagePageResult{}, ErrOrgMessageCursorMoved
	}

	for _, th := range p.Body.Threads {
		if strings.TrimSpace(th.ID) == "" {
			continue
		}
		closedSeen := ""
		if th.Status == "closed" {
			closedSeen = stamp
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO org_message_threads_local
			    (thread_id, subject, kind, topic, started_by, status, updated_at, received_at, closed_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(thread_id) DO UPDATE SET
			    subject = excluded.subject, kind = excluded.kind, topic = excluded.topic,
			    started_by = excluded.started_by, status = excluded.status,
			    updated_at = excluded.updated_at, received_at = excluded.received_at,
			    closed_seen_at = CASE
			        WHEN excluded.status <> 'closed' THEN ''
			        WHEN org_message_threads_local.closed_seen_at <> '' THEN org_message_threads_local.closed_seen_at
			        ELSE excluded.closed_seen_at END`,
			th.ID, th.Subject, orDefaultKind(th.Kind), th.Topic, th.StartedBy, orDefaultStatus(th.Status),
			th.UpdatedAt, stamp, closedSeen); err != nil {
			return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: thread: %w", err)
		}
	}

	next := p.Body.NextAfter
	if next < current {
		next = current
	}
	var inserted []OrgInboxMessage
	for _, m := range p.Body.Messages {
		if m.ID <= 0 || strings.TrimSpace(m.ThreadID) == "" {
			continue
		}
		if m.ID > next {
			next = m.ID
		}
		// A message whose thread header was not on the page still needs a
		// row to hang from; the next header that arrives fills it in.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO org_message_threads_local (thread_id, received_at) VALUES (?, ?)
			ON CONFLICT(thread_id) DO NOTHING`, m.ThreadID, stamp); err != nil {
			return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: thread stub: %w", err)
		}
		att := ""
		if len(m.Attachments) > 0 {
			raw, err := json.Marshal(m.Attachments)
			if err != nil {
				return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: attachments: %w", err)
			}
			att = string(raw)
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO org_messages_inbox
			    (message_id, thread_id, author_kind, author_name, body, require_ack, created_at,
			     client_msg_id, attachments_json, received_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(message_id) DO NOTHING`,
			m.ID, m.ThreadID, m.AuthorKind, m.AuthorName, m.Body, boolInt(m.RequireAck), m.CreatedAt,
			m.ClientMsgID, att, stamp)
		if err != nil {
			return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: message: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		inserted = append(inserted, OrgInboxMessage{
			ID: m.ID, ThreadID: m.ThreadID, AuthorKind: m.AuthorKind, AuthorName: m.AuthorName,
			Body: m.Body, RequireAck: m.RequireAck, CreatedAt: m.CreatedAt, ClientMsgID: m.ClientMsgID,
			Attachments: m.Attachments, ReceivedAt: stamp,
		})
		if m.AuthorKind == orgcontract.OrgMessageAuthorDeveloper && m.ClientMsgID != "" {
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM org_message_outbox WHERE client_msg_id = ? AND kind = 'post'`, m.ClientMsgID); err != nil {
				return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: outbox: %w", err)
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO org_message_rail
		    (id, org_id, subject, cursor, version, etag, key_fingerprint, policy_json,
		     fetch_state, last_error, last_attempt_at, last_ok_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'ok', '', ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		    org_id = excluded.org_id, subject = excluded.subject, cursor = excluded.cursor,
		    version = excluded.version, etag = excluded.etag, key_fingerprint = excluded.key_fingerprint,
		    policy_json = excluded.policy_json, fetch_state = 'ok', last_error = '',
		    last_attempt_at = excluded.last_attempt_at, last_ok_at = excluded.last_ok_at`,
		p.OrgID, p.Subject, next, p.Body.Version, p.ETag, p.KeyFingerprint, string(policyRaw), stamp, stamp); err != nil {
		return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: rail: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OrgMessagePageResult{}, fmt.Errorf("store.SaveOrgMessagePage: commit: %w", err)
	}
	return OrgMessagePageResult{Inserted: inserted, Cursor: next}, nil
}

// OrgInboxMessage is one stored message.
type OrgInboxMessage struct {
	ID          int64                              `json:"id"`
	ThreadID    string                             `json:"thread_id"`
	AuthorKind  string                             `json:"author_kind"`
	AuthorName  string                             `json:"author_name"`
	Body        string                             `json:"body"`
	RequireAck  bool                               `json:"require_ack"`
	CreatedAt   string                             `json:"created_at"`
	ClientMsgID string                             `json:"client_msg_id,omitempty"`
	Attachments []orgcontract.OrgMessageAttachment `json:"attachments"`
	ReceivedAt  string                             `json:"received_at"`
	ReadAt      string                             `json:"read_at,omitempty"`
	AckedAt     string                             `json:"acked_at,omitempty"`
}

// OrgMessageThreadSummary is one row of the thread list.
type OrgMessageThreadSummary struct {
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	Kind      string `json:"kind"`
	Topic     string `json:"topic,omitempty"`
	StartedBy string `json:"started_by"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
	// The newest stored message, whoever wrote it.
	LastAuthorKind string `json:"last_author_kind,omitempty"`
	LastAuthorName string `json:"last_author_name,omitempty"`
	LastPreview    string `json:"last_preview,omitempty"`
	LastAt         string `json:"last_at,omitempty"`
	// Messages is every stored message; Unread / NeedsAck count admin
	// messages only (the developer's own words are never "unread").
	Messages int `json:"messages"`
	Unread   int `json:"unread"`
	NeedsAck int `json:"needs_ack"`
	// Pending / Failed count this thread's outbox posts.
	Pending int `json:"pending"`
	Failed  int `json:"failed"`
}

// OrgMessageThreadFilter narrows ListOrgMessageThreads.
type OrgMessageThreadFilter struct {
	// Status is "open", "closed" or "" for both.
	Status string
	// Limit bounds the rows (0 = 200).
	Limit int
}

// orgMessageThreadSelect is the per-thread aggregate both the list and the
// detail read.
const orgMessageThreadSelect = `
	SELECT t.thread_id, t.subject, t.kind, t.topic, t.started_by, t.status, t.updated_at,
	       COALESCE(l.author_kind, ''), COALESCE(l.author_name, ''), COALESCE(l.body, ''), COALESCE(l.created_at, ''),
	       (SELECT COUNT(*) FROM org_messages_inbox m WHERE m.thread_id = t.thread_id),
	       (SELECT COUNT(*) FROM org_messages_inbox m WHERE m.thread_id = t.thread_id
	            AND m.author_kind = 'admin' AND m.read_at = ''),
	       (SELECT COUNT(*) FROM org_messages_inbox m WHERE m.thread_id = t.thread_id
	            AND m.author_kind = 'admin' AND m.require_ack = 1 AND m.acked_at = ''),
	       (SELECT COUNT(*) FROM org_message_outbox o WHERE o.kind = 'post'
	            AND (o.thread_id = t.thread_id OR o.result_thread_id = t.thread_id) AND o.state <> 'failed'),
	       (SELECT COUNT(*) FROM org_message_outbox o WHERE o.kind = 'post'
	            AND (o.thread_id = t.thread_id OR o.result_thread_id = t.thread_id) AND o.state = 'failed'),
	       COALESCE(l.created_at, t.updated_at) AS activity
	  FROM org_message_threads_local t
	  LEFT JOIN org_messages_inbox l ON l.message_id =
	       (SELECT MAX(message_id) FROM org_messages_inbox x WHERE x.thread_id = t.thread_id)`

func scanThreadSummary(sc interface{ Scan(...any) error }) (OrgMessageThreadSummary, error) {
	var t OrgMessageThreadSummary
	var activity string
	err := sc.Scan(&t.ID, &t.Subject, &t.Kind, &t.Topic, &t.StartedBy, &t.Status, &t.UpdatedAt,
		&t.LastAuthorKind, &t.LastAuthorName, &t.LastPreview, &t.LastAt,
		&t.Messages, &t.Unread, &t.NeedsAck, &t.Pending, &t.Failed, &activity)
	t.LastPreview = preview(t.LastPreview, 160)
	return t, err
}

// ListOrgMessageThreads returns threads, most recent activity first.
func (s *Store) ListOrgMessageThreads(ctx context.Context, f OrgMessageThreadFilter) ([]OrgMessageThreadSummary, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := orgMessageThreadSelect
	args := []any{}
	if f.Status != "" {
		q += ` WHERE t.status = ?`
		args = append(args, f.Status)
	}
	q += ` ORDER BY activity DESC, t.thread_id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListOrgMessageThreads: %w", err)
	}
	defer rows.Close()
	out := []OrgMessageThreadSummary{}
	for rows.Next() {
		t, err := scanThreadSummary(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListOrgMessageThreads: scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// OrgMessageThread is one thread with its messages and its outbox posts.
type OrgMessageThread struct {
	Thread   OrgMessageThreadSummary `json:"thread"`
	Messages []OrgInboxMessage       `json:"messages"`
	Outbox   []OrgMessageOutboxItem  `json:"outbox"`
}

// GetOrgMessageThread returns one thread; ok=false when it is not held.
func (s *Store) GetOrgMessageThread(ctx context.Context, id string) (OrgMessageThread, bool, error) {
	t, err := scanThreadSummary(s.db.QueryRowContext(ctx, orgMessageThreadSelect+` WHERE t.thread_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return OrgMessageThread{}, false, nil
	}
	if err != nil {
		return OrgMessageThread{}, false, fmt.Errorf("store.GetOrgMessageThread: %w", err)
	}
	out := OrgMessageThread{Thread: t, Messages: []OrgInboxMessage{}, Outbox: []OrgMessageOutboxItem{}}
	rows, err := s.db.QueryContext(ctx, `
		SELECT message_id, thread_id, author_kind, author_name, body, require_ack, created_at,
		       client_msg_id, attachments_json, received_at, read_at, acked_at
		  FROM org_messages_inbox WHERE thread_id = ? ORDER BY message_id`, id)
	if err != nil {
		return OrgMessageThread{}, false, fmt.Errorf("store.GetOrgMessageThread: messages: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var m OrgInboxMessage
		var ack int
		var att string
		if err := rows.Scan(&m.ID, &m.ThreadID, &m.AuthorKind, &m.AuthorName, &m.Body, &ack, &m.CreatedAt,
			&m.ClientMsgID, &att, &m.ReceivedAt, &m.ReadAt, &m.AckedAt); err != nil {
			return OrgMessageThread{}, false, fmt.Errorf("store.GetOrgMessageThread: scan: %w", err)
		}
		m.RequireAck = ack != 0
		m.Attachments = decodeAttachments(att)
		out.Messages = append(out.Messages, m)
	}
	if err := rows.Err(); err != nil {
		return OrgMessageThread{}, false, err
	}
	items, err := s.listOutbox(ctx, outboxThreadPosts, id, id)
	if err != nil {
		return OrgMessageThread{}, false, err
	}
	out.Outbox = items
	return out, true, nil
}

// OrgMessageThreadHeader returns one thread's subject and kind; ok=false
// when the thread is not held.
func (s *Store) OrgMessageThreadHeader(ctx context.Context, id string) (subject, kind string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT subject, kind FROM org_message_threads_local WHERE thread_id = ?`, id).Scan(&subject, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("store.OrgMessageThreadHeader: %w", err)
	}
	return subject, kind, true, nil
}

// OrgMessageOutboxItem is one queued post or receipt.
type OrgMessageOutboxItem struct {
	ClientMsgID      string                             `json:"id"`
	OrgID            string                             `json:"-"`
	Kind             string                             `json:"kind"`
	ThreadID         string                             `json:"thread_id,omitempty"`
	NewSubject       string                             `json:"new_subject,omitempty"`
	NewTopic         string                             `json:"new_topic,omitempty"`
	Body             string                             `json:"body,omitempty"`
	Attachments      []orgcontract.OrgMessageAttachment `json:"attachments"`
	ReceiptMessageID int64                              `json:"receipt_message_id,omitempty"`
	ReceiptState     string                             `json:"receipt_state,omitempty"`
	ReceiptAt        string                             `json:"receipt_at,omitempty"`
	CreatedAt        string                             `json:"created_at"`
	State            string                             `json:"state"`
	Attempts         int                                `json:"attempts"`
	LastError        string                             `json:"last_error,omitempty"`
	LastErrorCode    string                             `json:"last_error_code,omitempty"`
	LastAttemptAt    string                             `json:"last_attempt_at,omitempty"`
	SentAt           string                             `json:"sent_at,omitempty"`
	ResultMessageID  int64                              `json:"result_message_id,omitempty"`
	ResultThreadID   string                             `json:"result_thread_id,omitempty"`
}

const outboxColumns = `client_msg_id, org_id, kind, thread_id, new_subject, new_topic, body, attachments_json,
	receipt_message_id, receipt_state, receipt_at, created_at, state, attempts, last_error, last_error_code,
	last_attempt_at, sent_at, result_message_id, result_thread_id`

func scanOutbox(sc interface{ Scan(...any) error }) (OrgMessageOutboxItem, error) {
	var o OrgMessageOutboxItem
	var att string
	err := sc.Scan(&o.ClientMsgID, &o.OrgID, &o.Kind, &o.ThreadID, &o.NewSubject, &o.NewTopic, &o.Body, &att,
		&o.ReceiptMessageID, &o.ReceiptState, &o.ReceiptAt, &o.CreatedAt, &o.State, &o.Attempts, &o.LastError,
		&o.LastErrorCode, &o.LastAttemptAt, &o.SentAt, &o.ResultMessageID, &o.ResultThreadID)
	o.Attachments = decodeAttachments(att)
	return o, err
}

// The outbox reads, each a constant query.
const (
	outboxSelect        = `SELECT ` + outboxColumns + ` FROM org_message_outbox WHERE `
	outboxOrder         = ` ORDER BY created_at, client_msg_id`
	outboxThreadPosts   = outboxSelect + `kind = 'post' AND (thread_id = ? OR result_thread_id = ?)` + outboxOrder
	outboxPendingForOrg = outboxSelect + `state = 'queued' AND org_id = ?` + outboxOrder
	outboxAllPosts      = outboxSelect + `kind = 'post'` + outboxOrder
)

func (s *Store) listOutbox(ctx context.Context, query string, args ...any) ([]OrgMessageOutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.listOutbox: %w", err)
	}
	defer rows.Close()
	out := []OrgMessageOutboxItem{}
	for rows.Next() {
		o, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("store.listOutbox: scan: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// OrgMessagePostDraft is what the developer wrote: a reply (ThreadID) or a
// new thread (NewSubject + NewTopic). ClientMsgID is minted by the caller.
type OrgMessagePostDraft struct {
	ClientMsgID string
	OrgID       string
	ThreadID    string
	NewSubject  string
	NewTopic    string
	Body        string
	Attachments []orgcontract.OrgMessageAttachment
	Now         time.Time
}

// validate applies the wire contract's limits.
func (d *OrgMessagePostDraft) validate() error {
	d.ThreadID = strings.TrimSpace(d.ThreadID)
	d.NewSubject = strings.TrimSpace(d.NewSubject)
	d.NewTopic = strings.TrimSpace(d.NewTopic)
	d.Body = strings.TrimSpace(d.Body)
	switch {
	case strings.TrimSpace(d.ClientMsgID) == "" || len(d.ClientMsgID) > 128:
		return fmt.Errorf("%w: client id is required", ErrOrgMessageInvalid)
	case strings.TrimSpace(d.OrgID) == "":
		return fmt.Errorf("%w: not enrolled", ErrOrgMessageInvalid)
	case (d.ThreadID == "") == (d.NewSubject == ""):
		return fmt.Errorf("%w: a message is either a reply to a thread or a new thread with a subject", ErrOrgMessageInvalid)
	case d.Body == "":
		return fmt.Errorf("%w: the message is empty", ErrOrgMessageInvalid)
	case len(d.Body) > orgcontract.OrgMessageMaxBody:
		return fmt.Errorf("%w: the message is longer than %d bytes", ErrOrgMessageInvalid, orgcontract.OrgMessageMaxBody)
	case len(d.NewSubject) > orgcontract.OrgMessageMaxSubject:
		return fmt.Errorf("%w: the subject is longer than %d bytes", ErrOrgMessageInvalid, orgcontract.OrgMessageMaxSubject)
	case d.ThreadID == "" && d.NewTopic == "":
		return fmt.Errorf("%w: pick a topic", ErrOrgMessageInvalid)
	case len(d.Attachments) > orgcontract.OrgMessageMaxAttachments:
		return fmt.Errorf("%w: at most %d attachments", ErrOrgMessageInvalid, orgcontract.OrgMessageMaxAttachments)
	case !utf8.ValidString(d.Body) || !utf8.ValidString(d.NewSubject):
		return fmt.Errorf("%w: the text is not valid UTF-8", ErrOrgMessageInvalid)
	}
	for _, a := range d.Attachments {
		if strings.TrimSpace(a.Type) == "" || strings.TrimSpace(a.Ref) == "" {
			return fmt.Errorf("%w: an attachment needs a type and a reference", ErrOrgMessageInvalid)
		}
	}
	return nil
}

// EnqueueOrgMessagePost writes a post into the outbox (state queued). A
// second call with the same ClientMsgID returns the existing row unchanged,
// so a double-submitted form never queues twice.
func (s *Store) EnqueueOrgMessagePost(ctx context.Context, d OrgMessagePostDraft) (OrgMessageOutboxItem, error) {
	if existing, ok, err := s.GetOrgMessageOutboxItem(ctx, d.ClientMsgID); err != nil {
		return OrgMessageOutboxItem{}, err
	} else if ok {
		return existing, nil
	}
	if err := d.validate(); err != nil {
		return OrgMessageOutboxItem{}, err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM org_message_outbox WHERE kind = 'post' AND state <> 'sent'`).Scan(&n); err != nil {
		return OrgMessageOutboxItem{}, fmt.Errorf("store.EnqueueOrgMessagePost: count: %w", err)
	}
	if n >= MaxOrgMessageOutboxPosts {
		return OrgMessageOutboxItem{}, ErrOrgMessageOutboxFull
	}
	att := ""
	if len(d.Attachments) > 0 {
		raw, err := json.Marshal(d.Attachments)
		if err != nil {
			return OrgMessageOutboxItem{}, fmt.Errorf("store.EnqueueOrgMessagePost: attachments: %w", err)
		}
		att = string(raw)
	}
	now := d.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO org_message_outbox
		    (client_msg_id, org_id, kind, thread_id, new_subject, new_topic, body, attachments_json, created_at)
		VALUES (?, ?, 'post', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(client_msg_id) DO NOTHING`,
		d.ClientMsgID, d.OrgID, d.ThreadID, d.NewSubject, d.NewTopic, d.Body, att, stampTime(now)); err != nil {
		return OrgMessageOutboxItem{}, fmt.Errorf("store.EnqueueOrgMessagePost: %w", err)
	}
	item, _, err := s.GetOrgMessageOutboxItem(ctx, d.ClientMsgID)
	return item, err
}

// GetOrgMessageOutboxItem returns one outbox row; ok=false when absent.
func (s *Store) GetOrgMessageOutboxItem(ctx context.Context, id string) (OrgMessageOutboxItem, bool, error) {
	o, err := scanOutbox(s.db.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM org_message_outbox WHERE client_msg_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return OrgMessageOutboxItem{}, false, nil
	}
	if err != nil {
		return OrgMessageOutboxItem{}, false, fmt.Errorf("store.GetOrgMessageOutboxItem: %w", err)
	}
	return o, true, nil
}

// PendingOrgMessageOutbox returns the rows a flush sends for orgID, oldest
// first: queued posts and receipts. Failed rows wait for the developer.
func (s *Store) PendingOrgMessageOutbox(ctx context.Context, orgID string) ([]OrgMessageOutboxItem, error) {
	return s.listOutbox(ctx, outboxPendingForOrg, orgID)
}

// ListOrgMessageOutboxPosts returns every post not yet back from the pull
// (queued, sent or failed), oldest first: the Messages page shows replies in
// flight and developer-started threads the org has not answered yet.
func (s *Store) ListOrgMessageOutboxPosts(ctx context.Context) ([]OrgMessageOutboxItem, error) {
	return s.listOutbox(ctx, outboxAllPosts)
}

// MarkOrgMessageOutboxSent records the org's acceptance. A receipt row is
// done and goes; a post row keeps its result ids until the pull brings the
// stored message back (SaveOrgMessagePage drops it then).
func (s *Store) MarkOrgMessageOutboxSent(ctx context.Context, id string, messageID int64, threadID string, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_message_outbox WHERE client_msg_id = ? AND kind = 'receipt'`, id); err != nil {
		return fmt.Errorf("store.MarkOrgMessageOutboxSent: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE org_message_outbox
		   SET state = 'sent', sent_at = ?, result_message_id = ?, result_thread_id = ?,
		       attempts = attempts + 1, last_attempt_at = ?, last_error = '', last_error_code = ''
		 WHERE client_msg_id = ? AND kind = 'post'`,
		stampTime(now), messageID, threadID, stampTime(now), id); err != nil {
		return fmt.Errorf("store.MarkOrgMessageOutboxSent: %w", err)
	}
	return nil
}

// NoteOrgMessageOutboxAttempt records an attempt that did not land. failed
// moves the row to the failed state (refused on its merits: not retried
// until the developer asks); otherwise it stays queued for the next flush.
func (s *Store) NoteOrgMessageOutboxAttempt(ctx context.Context, id, errText, code string, failed bool, now time.Time) error {
	state := OrgMessageOutboxQueued
	if failed {
		state = OrgMessageOutboxFailed
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE org_message_outbox
		   SET attempts = attempts + 1, last_error = ?, last_error_code = ?, last_attempt_at = ?, state = ?
		 WHERE client_msg_id = ? AND state <> 'sent'`,
		boundText(errText, 500), code, stampTime(now), state, id); err != nil {
		return fmt.Errorf("store.NoteOrgMessageOutboxAttempt: %w", err)
	}
	return nil
}

// RequeueOrgMessageOutbox moves a failed row back to queued (the
// developer's Retry). ok=false when the row is absent or not failed.
func (s *Store) RequeueOrgMessageOutbox(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE org_message_outbox SET state = 'queued', last_error = '', last_error_code = ''
		 WHERE client_msg_id = ? AND state = 'failed'`, id)
	if err != nil {
		return false, fmt.Errorf("store.RequeueOrgMessageOutbox: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DiscardOrgMessageOutbox removes a row the org has not accepted (queued or
// failed). A sent row is not discardable: the org already holds it.
func (s *Store) DiscardOrgMessageOutbox(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM org_message_outbox WHERE client_msg_id = ? AND state <> 'sent'`, id)
	if err != nil {
		return false, fmt.Errorf("store.DiscardOrgMessageOutbox: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// receiptID is the deterministic outbox id of one receipt, so marking the
// same message read twice queues one receipt.
func receiptID(messageID int64, state string) string {
	return "receipt:" + strconv.FormatInt(messageID, 10) + ":" + state
}

func queueReceipt(ctx context.Context, tx *sql.Tx, orgID string, messageID int64, state, at string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO org_message_outbox
		    (client_msg_id, org_id, kind, receipt_message_id, receipt_state, receipt_at, created_at)
		VALUES (?, ?, 'receipt', ?, ?, ?, ?)
		ON CONFLICT(client_msg_id) DO NOTHING`,
		receiptID(messageID, state), orgID, messageID, state, at, at)
	return err
}

// MarkOrgMessageThreadRead marks every unread admin message in the thread
// read and, when queueReceipts, queues one read receipt per message. It
// returns how many messages changed.
func (s *Store) MarkOrgMessageThreadRead(ctx context.Context, threadID, orgID string, queueReceipts bool, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_message_threads_local WHERE thread_id = ?`, threadID).Scan(&exists); err != nil {
		return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: %w", err)
	}
	if exists == 0 {
		return 0, ErrOrgMessageNotFound
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT message_id FROM org_messages_inbox
		 WHERE thread_id = ? AND author_kind = 'admin' AND read_at = '' ORDER BY message_id`, threadID)
	if err != nil {
		return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	stamp := stampTime(now)
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE org_messages_inbox SET read_at = ? WHERE message_id = ?`, stamp, id); err != nil {
			return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: %w", err)
		}
		if queueReceipts {
			if err := queueReceipt(ctx, tx, orgID, id, orgcontract.OrgMessageReceiptRead, stamp); err != nil {
				return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: receipt: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.MarkOrgMessageThreadRead: commit: %w", err)
	}
	return len(ids), nil
}

// AckOrgMessage acknowledges one admin message that asked for it (marking
// it read too) and queues the acknowledged receipt. Acknowledging is an
// explicit act, so its receipt is always queued. Acknowledging twice is a
// no-op that keeps the first time.
func (s *Store) AckOrgMessage(ctx context.Context, messageID int64, orgID string, now time.Time) (OrgInboxMessage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OrgInboxMessage{}, fmt.Errorf("store.AckOrgMessage: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var m OrgInboxMessage
	var ack int
	var att string
	err = tx.QueryRowContext(ctx, `
		SELECT message_id, thread_id, author_kind, author_name, body, require_ack, created_at,
		       client_msg_id, attachments_json, received_at, read_at, acked_at
		  FROM org_messages_inbox WHERE message_id = ?`, messageID).
		Scan(&m.ID, &m.ThreadID, &m.AuthorKind, &m.AuthorName, &m.Body, &ack, &m.CreatedAt,
			&m.ClientMsgID, &att, &m.ReceivedAt, &m.ReadAt, &m.AckedAt)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && m.AuthorKind != orgcontract.OrgMessageAuthorAdmin) {
		return OrgInboxMessage{}, ErrOrgMessageNotFound
	}
	if err != nil {
		return OrgInboxMessage{}, fmt.Errorf("store.AckOrgMessage: %w", err)
	}
	m.RequireAck = ack != 0
	m.Attachments = decodeAttachments(att)
	if !m.RequireAck {
		return OrgInboxMessage{}, ErrOrgMessageAckNotRequested
	}
	if m.AckedAt != "" {
		return m, nil
	}
	stamp := stampTime(now)
	m.AckedAt = stamp
	if m.ReadAt == "" {
		m.ReadAt = stamp
	}
	if _, err := tx.ExecContext(ctx, `UPDATE org_messages_inbox SET acked_at = ?, read_at = ? WHERE message_id = ?`,
		m.AckedAt, m.ReadAt, messageID); err != nil {
		return OrgInboxMessage{}, fmt.Errorf("store.AckOrgMessage: %w", err)
	}
	if err := queueReceipt(ctx, tx, orgID, messageID, orgcontract.OrgMessageReceiptAcknowledged, stamp); err != nil {
		return OrgInboxMessage{}, fmt.Errorf("store.AckOrgMessage: receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OrgInboxMessage{}, fmt.Errorf("store.AckOrgMessage: commit: %w", err)
	}
	return m, nil
}

// OrgMessageNewest names the newest unread admin message.
type OrgMessageNewest struct {
	ThreadID   string `json:"thread_id"`
	MessageID  int64  `json:"message_id"`
	Subject    string `json:"subject"`
	AuthorName string `json:"author_name"`
	Kind       string `json:"kind"`
	CreatedAt  string `json:"created_at"`
	RequireAck bool   `json:"require_ack"`
}

// OrgMessageSummary is the cheap read behind the VS Code badge, the status
// line and the nav badge. Counts are of admin messages only.
type OrgMessageSummary struct {
	Unread        int `json:"unread"`
	UnreadThreads int `json:"unread_threads"`
	NeedsAck      int `json:"needs_ack"`
	// UnreadAlerts counts unread messages in alert threads (what a push
	// surface shows under [messages].alerts_only).
	UnreadAlerts int `json:"unread_alerts"`
	// FailedOutbox counts posts the org refused (the "Reply not sent" state).
	FailedOutbox int               `json:"failed_outbox"`
	Newest       *OrgMessageNewest `json:"newest"`
	NewestAlert  *OrgMessageNewest `json:"newest_alert"`
}

const unreadAdminSelect = `
	SELECT m.thread_id, m.message_id, COALESCE(t.subject, ''), m.author_name, COALESCE(t.kind, 'note'),
	       m.created_at, m.require_ack
	  FROM org_messages_inbox m
	  LEFT JOIN org_message_threads_local t ON t.thread_id = m.thread_id
	 WHERE m.author_kind = 'admin' AND m.read_at = ''`

func scanNewest(sc interface{ Scan(...any) error }) (*OrgMessageNewest, error) {
	var n OrgMessageNewest
	var ack int
	err := sc.Scan(&n.ThreadID, &n.MessageID, &n.Subject, &n.AuthorName, &n.Kind, &n.CreatedAt, &ack)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.RequireAck = ack != 0
	return &n, nil
}

// OrgMessageSummary returns the counts and the newest unread message.
func (s *Store) OrgMessageSummary(ctx context.Context) (OrgMessageSummary, error) {
	var out OrgMessageSummary
	if err := s.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM org_messages_inbox WHERE author_kind = 'admin' AND read_at = ''),
		  (SELECT COUNT(DISTINCT thread_id) FROM org_messages_inbox WHERE author_kind = 'admin' AND read_at = ''),
		  (SELECT COUNT(*) FROM org_messages_inbox WHERE author_kind = 'admin' AND require_ack = 1 AND acked_at = ''),
		  (SELECT COUNT(*) FROM org_messages_inbox m JOIN org_message_threads_local t ON t.thread_id = m.thread_id
		    WHERE m.author_kind = 'admin' AND m.read_at = '' AND t.kind = 'alert'),
		  (SELECT COUNT(*) FROM org_message_outbox WHERE kind = 'post' AND state = 'failed')`).
		Scan(&out.Unread, &out.UnreadThreads, &out.NeedsAck, &out.UnreadAlerts, &out.FailedOutbox); err != nil {
		return OrgMessageSummary{}, fmt.Errorf("store.OrgMessageSummary: %w", err)
	}
	var err error
	if out.Newest, err = scanNewest(s.db.QueryRowContext(ctx, unreadAdminSelect+` ORDER BY m.message_id DESC LIMIT 1`)); err != nil {
		return OrgMessageSummary{}, fmt.Errorf("store.OrgMessageSummary: newest: %w", err)
	}
	if out.NewestAlert, err = scanNewest(s.db.QueryRowContext(ctx, unreadAdminSelect+` AND t.kind = 'alert' ORDER BY m.message_id DESC LIMIT 1`)); err != nil {
		return OrgMessageSummary{}, fmt.Errorf("store.OrgMessageSummary: newest alert: %w", err)
	}
	return out, nil
}

// OrgMessageUnreadThread is one thread with unread admin messages, as the
// notification bell reads it.
type OrgMessageUnreadThread struct {
	ThreadID      string
	Subject       string
	Kind          string
	NewestID      int64
	NewestAuthor  string
	NewestAt      string
	Unread        int
	NeedsAck      int
	AwaitingReply bool
}

// ListUnreadOrgMessageThreads returns every thread holding unread admin
// messages (or an unacknowledged one), newest first, bounded.
func (s *Store) ListUnreadOrgMessageThreads(ctx context.Context, limit int) ([]OrgMessageUnreadThread, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.thread_id, COALESCE(t.subject, ''), COALESCE(t.kind, 'note'),
		       MAX(m.message_id),
		       SUM(CASE WHEN m.read_at = '' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN m.require_ack = 1 AND m.acked_at = '' THEN 1 ELSE 0 END)
		  FROM org_messages_inbox m
		  LEFT JOIN org_message_threads_local t ON t.thread_id = m.thread_id
		 WHERE m.author_kind = 'admin' AND (m.read_at = '' OR (m.require_ack = 1 AND m.acked_at = ''))
		 GROUP BY m.thread_id
		 ORDER BY MAX(m.message_id) DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListUnreadOrgMessageThreads: %w", err)
	}
	defer rows.Close()
	out := []OrgMessageUnreadThread{}
	for rows.Next() {
		var u OrgMessageUnreadThread
		if err := rows.Scan(&u.ThreadID, &u.Subject, &u.Kind, &u.NewestID, &u.Unread, &u.NeedsAck); err != nil {
			return nil, fmt.Errorf("store.ListUnreadOrgMessageThreads: scan: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.db.QueryRowContext(ctx, `
			SELECT author_name, created_at FROM org_messages_inbox WHERE message_id = ?`, out[i].NewestID).
			Scan(&out[i].NewestAuthor, &out[i].NewestAt); err != nil {
			return nil, fmt.Errorf("store.ListUnreadOrgMessageThreads: newest: %w", err)
		}
	}
	return out, nil
}

// PruneOrgMessages drops closed threads (with their messages and outbox
// posts) the node first saw closed more than retentionDays ago (0 or less =
// DefaultOrgMessageLocalRetentionDays), and sent posts the pull never
// brought back within sentPostKeep. Returns the threads removed.
func (s *Store) PruneOrgMessages(ctx context.Context, retentionDays int, now time.Time) (int, error) {
	if retentionDays <= 0 {
		retentionDays = DefaultOrgMessageLocalRetentionDays
	}
	cutoff := stampTime(now.Add(-time.Duration(retentionDays) * 24 * time.Hour))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PruneOrgMessages: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	const old = `SELECT thread_id FROM org_message_threads_local
		WHERE status = 'closed' AND closed_seen_at <> '' AND closed_seen_at < ?`
	for _, q := range []string{
		`DELETE FROM org_messages_inbox WHERE thread_id IN (` + old + `)`,
		`DELETE FROM org_message_outbox WHERE kind = 'post' AND thread_id IN (` + old + `)`,
	} {
		if _, err := tx.ExecContext(ctx, q, cutoff); err != nil {
			return 0, fmt.Errorf("store.PruneOrgMessages: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM org_message_threads_local
		WHERE status = 'closed' AND closed_seen_at <> '' AND closed_seen_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store.PruneOrgMessages: threads: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_message_outbox WHERE state = 'sent' AND sent_at < ?`,
		stampTime(now.Add(-sentPostKeep))); err != nil {
		return 0, fmt.Errorf("store.PruneOrgMessages: sent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PruneOrgMessages: commit: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// clearOrgMessages drops every message table (an enrolment identity
// ended): the messages were the org speaking to one member, and the outbox
// holds words meant for that org only.
func (s *Store) clearOrgMessages(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM org_message_outbox`,
		`DELETE FROM org_messages_inbox`,
		`DELETE FROM org_message_threads_local`,
		`DELETE FROM org_message_rail`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("store.clearOrgMessages: %w", err)
		}
	}
	return nil
}

func decodeAttachments(raw string) []orgcontract.OrgMessageAttachment {
	out := []orgcontract.OrgMessageAttachment{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []orgcontract.OrgMessageAttachment{}
	}
	return out
}

func stampTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func orDefaultKind(k string) string {
	if strings.TrimSpace(k) == "" {
		return orgcontract.OrgMessageKindNote
	}
	return k
}

func orDefaultStatus(s string) string {
	if strings.TrimSpace(s) == "" {
		return "open"
	}
	return s
}

// boundText caps a stored error string rune-safely.
func boundText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// preview is a one-line, bounded excerpt for the thread list.
func preview(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
