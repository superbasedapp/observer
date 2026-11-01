package orgcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Admin and developer messaging wire (docs/plans/admin-developer-messaging-
// plan-2026-10-15.md section 17.3).
//
// Delivery is a PULL: the node calls GET /api/agent/messages?after=<id> with
// its bearer, and the server answers a signed, per-caller OrgMessageDoc. A
// reply, a developer-started thread and read/acknowledge receipts travel back
// as POSTs from the node's outbox. No new inbound port exists on the node.

// Message kinds. The server owns the closed set; the wire carries the string
// so an older node renders an unknown kind as a plain note.
const (
	// OrgMessageKindNote is a plain message with no action needed.
	OrgMessageKindNote = "note"
	// OrgMessageKindCoaching is a suggestion about a better way to work.
	OrgMessageKindCoaching = "coaching"
	// OrgMessageKindAlert is something that needs attention now.
	OrgMessageKindAlert = "alert"
)

// Author kinds.
const (
	// OrgMessageAuthorAdmin marks a message written by an org admin.
	OrgMessageAuthorAdmin = "admin"
	// OrgMessageAuthorDeveloper marks a message written by the developer.
	OrgMessageAuthorDeveloper = "developer"
)

// Receipt states a node may report, lowest to highest. A receipt never
// lowers a state the server already holds.
const (
	// OrgMessageReceiptRead is reported when the developer opens the thread.
	OrgMessageReceiptRead = "read"
	// OrgMessageReceiptAcknowledged is reported when the developer presses
	// Acknowledge on a message that asked for it.
	OrgMessageReceiptAcknowledged = "acknowledged"
)

// OrgMessageAttachment is a typed reference to a real object, never a copy
// of its content. Type is one of session, turn, model, guard_event, project,
// budget, request (the server owns the closed set). Ref is the object's
// id in the vocabulary both dashboards already use (a session id, a
// "session_id#message_key" for a turn, a model id, ...). Label is a short
// human label built from data the node itself shipped. Excerpt is set only
// when the org already holds that text and the author was allowed to see it.
type OrgMessageAttachment struct {
	Type    string `json:"type"`
	Ref     string `json:"ref"`
	Label   string `json:"label,omitempty"`
	Excerpt string `json:"excerpt,omitempty"`
}

// OrgMessageRow is one message in a thread. ID is the server's org-wide,
// monotonically increasing message id and doubles as the pull cursor.
type OrgMessageRow struct {
	ID          int64                  `json:"id"`
	ThreadID    string                 `json:"thread_id"`
	AuthorKind  string                 `json:"author_kind"`
	AuthorName  string                 `json:"author_name"`
	Body        string                 `json:"body"`
	RequireAck  bool                   `json:"require_ack,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	ClientMsgID string                 `json:"client_msg_id,omitempty"`
	Attachments []OrgMessageAttachment `json:"attachments,omitempty"`
}

// OrgMessageThreadRow is the current header of a thread the pull touched.
type OrgMessageThreadRow struct {
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	Kind      string `json:"kind"`
	Topic     string `json:"topic,omitempty"`
	StartedBy string `json:"started_by"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
}

// OrgMessageNodePolicy is the developer-facing subset of the org's message
// settings: what the node's "Ask my admin" form may offer and how long the
// node keeps closed threads. The server enforces the same rules on POST; the
// node uses this only to shape its UI.
type OrgMessageNodePolicy struct {
	DevThreadsAllowed   bool     `json:"dev_threads_allowed"`
	Topics              []string `json:"topics,omitempty"`
	RequestTopics       []string `json:"request_topics,omitempty"`
	ReadReceiptsDefault bool     `json:"read_receipts_default"`
	RetentionDays       int      `json:"retention_days"`
}

// OrgMessageBody is the signed body of GET /api/agent/messages.
//
// Canonicalisation follows the budget rail's rule (budgetpolicy.go): new
// fields are APPENDED with omitempty, never inserted, so an old body keeps
// verifying on a new node.
type OrgMessageBody struct {
	Version   int64                 `json:"version"`
	After     int64                 `json:"after"`
	NextAfter int64                 `json:"next_after"`
	More      bool                  `json:"more,omitempty"`
	Threads   []OrgMessageThreadRow `json:"threads,omitempty"`
	Messages  []OrgMessageRow       `json:"messages,omitempty"`
	Policy    OrgMessageNodePolicy  `json:"policy"`
	IssuedAt  string                `json:"issued_at"`
}

// OrgMessageDoc is the wire document: the body inline plus the org's
// Ed25519 signature (base64 std encoding).
type OrgMessageDoc struct {
	OrgMessageBody
	Signature string `json:"signature"`
}

// orgMessageSigningDomain separates message signatures from every other use
// of the org key, so a signature minted on another rail never verifies here.
const orgMessageSigningDomain = "sbo-org-message-v1"

// OrgMessageSigningMessage returns the bytes signed over a message body:
//
//	SHA-256( domain || 0x00 || orgID || 0x00 || subject || 0x00 || bodyJSON )
//
// The SUBJECT is bound because the body is per developer: a genuine body
// handed to another member must not verify for them.
func OrgMessageSigningMessage(orgID, subject string, body OrgMessageBody) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("orgcontract.OrgMessageSigningMessage: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(orgMessageSigningDomain))
	h.Write([]byte{0})
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write(raw)
	return h.Sum(nil), nil
}

// SignOrgMessages returns the wire document for one caller.
func SignOrgMessages(priv ed25519.PrivateKey, orgID, subject string, body OrgMessageBody) (OrgMessageDoc, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return OrgMessageDoc{}, errors.New("orgcontract.SignOrgMessages: bad private key size")
	}
	msg, err := OrgMessageSigningMessage(orgID, subject, body)
	if err != nil {
		return OrgMessageDoc{}, err
	}
	return OrgMessageDoc{
		OrgMessageBody: body,
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}, nil
}

// ErrOrgMessageSignature is returned by VerifyOrgMessages when the document
// does not verify for this (orgID, subject). The node keeps what it already
// holds and stores nothing from the document.
var ErrOrgMessageSignature = errors.New("orgcontract: org message signature does not verify")

// VerifyOrgMessages checks doc's signature against pub for (orgID, subject).
// The TOFU pin on pub stays owned by the node's pin check, not here.
func VerifyOrgMessages(pub ed25519.PublicKey, orgID, subject string, doc OrgMessageDoc) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("orgcontract.VerifyOrgMessages: bad public key size")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return fmt.Errorf("orgcontract.VerifyOrgMessages: %w", err)
	}
	msg, err := OrgMessageSigningMessage(orgID, subject, doc.OrgMessageBody)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrOrgMessageSignature
	}
	return nil
}

// OrgMessageDigest is the ETag substrate for GET /api/agent/messages: sha256
// hex of the body without IssuedAt, so an unchanged inbox answers 304 even
// though every document is re-minted with a fresh timestamp.
func OrgMessageDigest(body OrgMessageBody) (string, error) {
	body.IssuedAt = ""
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("orgcontract.OrgMessageDigest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// OrgMessageNewThread opens a developer-started thread.
type OrgMessageNewThread struct {
	Subject string `json:"subject"`
	Topic   string `json:"topic"`
}

// OrgMessagePost is the body of POST /api/agent/messages: exactly one of
// ThreadID (a reply) or NewThread (a developer-started thread) is set.
// ClientMsgID is minted on the node and makes a retry idempotent.
type OrgMessagePost struct {
	ClientMsgID string                 `json:"client_msg_id"`
	ThreadID    string                 `json:"thread_id,omitempty"`
	NewThread   *OrgMessageNewThread   `json:"new_thread,omitempty"`
	Body        string                 `json:"body"`
	Attachments []OrgMessageAttachment `json:"attachments,omitempty"`
}

// OrgMessagePostResult is the answer to OrgMessagePost. A retried post
// returns the original ids.
type OrgMessagePostResult struct {
	MessageID int64  `json:"message_id"`
	ThreadID  string `json:"thread_id"`
}

// OrgMessageReceipt marks one admin message read or acknowledged.
type OrgMessageReceipt struct {
	MessageID int64  `json:"message_id"`
	State     string `json:"state"`
	At        string `json:"at"`
}

// OrgMessageReceipts is the body of POST /api/agent/messages/receipts.
type OrgMessageReceipts struct {
	Receipts []OrgMessageReceipt `json:"receipts"`
}

// Refusal codes a POST may answer with (JSON {"error": code}).
const (
	// OrgMessageErrThreadsDisabled: the org does not let this developer
	// start threads.
	OrgMessageErrThreadsDisabled = "threads_disabled"
	// OrgMessageErrTopicNotAllowed: the topic is not in the org's list.
	OrgMessageErrTopicNotAllowed = "topic_not_allowed"
	// OrgMessageErrThreadClosed: replies to a closed thread are refused.
	OrgMessageErrThreadClosed = "thread_closed"
	// OrgMessageErrNotFound: the thread is not the caller's.
	OrgMessageErrNotFound = "not_found"
)

// Limits shared by both ends.
const (
	// OrgMessageMaxBody bounds a message body in bytes.
	OrgMessageMaxBody = 8000
	// OrgMessageMaxSubject bounds a subject in bytes.
	OrgMessageMaxSubject = 200
	// OrgMessageMaxAttachments bounds attachments per message.
	OrgMessageMaxAttachments = 8
	// OrgMessagePageSize bounds messages per pull page.
	OrgMessagePageSize = 200
)
