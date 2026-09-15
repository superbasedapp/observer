package grokbot

import "encoding/json"

// blobEnvelope is the wrapper every sand-client-persistence blob shares.
type blobEnvelope struct {
	SchemaVersion int             `json:"schemaVersion"`
	Value         json.RawMessage `json:"value"`
}

// transcriptValue is the `value` of a transcript.replicas blob.
type transcriptValue struct {
	Entries []transcriptEntry `json:"entries"`
	// EpochHint identifies the replication epoch. A change means the
	// transcript was reset/re-replicated server-side, so any cursor we hold
	// no longer indexes the same sequence.
	EpochHint string `json:"epochHint"`
	// AcceptedSequenceHint is the server-accepted high-water mark. Recorded
	// for diagnostics only.
	AcceptedSequenceHint int `json:"acceptedSequenceHint"`
	// PersistedAt is Unix MILLISECONDS. Used as a timestamp floor for
	// entries that somehow carry none.
	PersistedAt int64 `json:"persistedAt"`
}

// transcriptEntry is one element of entries[].
//
// The `kind` union is exhaustive, transcribed from the app's own
// isValidTranscriptEntry validator (not merely from what a capture happened to
// contain):
//
//	message        requires content (string)
//	send-message   requires message (object)
//	tool-call      requires name (string)
//	user-attachment requires file_path (string)
//	notice         requires text (string)
//	event          requires event.type (string)
//	feedback       requires requestId (string)
//	voice-call     requires call.callId (string)
//
// ⚠ The `send-message` naming is inverted from the intuitive reading. It is
// the AGENT's outbound message to the user, NOT a message the user sent. The
// user's own turns are kind:"message" with role:"user". This is not an
// inference — it is the app's own role function:
//
//	kind === "message"          ? (fromAgent/fromUser != null ? "assistant" : entry.role)
//	: kind === "send-message"   ? "assistant"
//	: kind === "user-attachment" ? "user"
//	: "other"
type transcriptEntry struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	TimestampMs int64  `json:"timestampMs"`

	// kind=message
	Role    string `json:"role"`
	Content string `json:"content"`
	// IsStreaming marks a message still being written. Such an entry is
	// in-flight: its Content is a truncated prefix, so it is not ingested
	// until it settles.
	IsStreaming bool `json:"isStreaming"`
	// FromAgent / FromUser are group-conversation forwarding markers. Per
	// the app's role function, a `message` with either set is attributed to
	// the assistant regardless of its own Role field.
	FromAgent json.RawMessage `json:"fromAgent"`
	FromUser  json.RawMessage `json:"fromUser"`
	// RichText is a TipTap/ProseMirror document duplicating Content.
	// Declared so its presence is documented; deliberately NOT ingested.
	RichText string `json:"richText"`

	// kind=send-message
	Message *sendMessage `json:"message"`
	// BoxInstruction is the remote sandbox handing control back to the
	// human for an interactive step (e.g. an interactive sign-in).
	BoxInstruction string `json:"boxInstruction"`
	BoxResolution  string `json:"boxResolution"`

	// kind=tool-call. The box keeps arguments and results; only these
	// three fields ever reach the desktop.
	Name    string `json:"name"`
	Status  string `json:"status"`
	Summary string `json:"summary"`

	// kind=user-attachment
	FilePath string `json:"file_path"`
	FileName string `json:"file_name"`

	// kind=notice
	Text string `json:"text"`

	// kind=event
	Event *transcriptEvent `json:"event"`
}

// sendMessage is the payload of a send-message entry.
//
// Type union, from the app's own text-extraction switch:
//
//	text | attachment | widget | cursor-agent | secret-request | user-form
//	| email-draft | slack-draft | permission-request | auto-review-approval
//	| local-tool-permission | connector
//
// Only "text" carries a plain Content string. Every other variant is
// represented by a type-named placeholder rather than by reaching into its
// payload — notably "secret-request", whose body is credential-request
// material we deliberately never dereference.
type sendMessage struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

type transcriptEvent struct {
	Type string `json:"type"`
	// Action / AutomationName are the observed automation-changed fields.
	Action         string `json:"action"`
	AutomationName string `json:"automationName"`
}

// inFlight reports whether an entry is still being written, using the app's
// own predicate:
//
//	kind === "message" && isStreaming || kind === "tool-call" && status === "pending"
//
// An in-flight entry is not ingested and does not advance the cursor, so its
// settled form is picked up on a later tick. Persisting the streaming prefix
// instead would be unfixable: the store's action upsert cannot rewrite a
// target on conflict.
func (e transcriptEntry) inFlight() bool {
	switch e.Kind {
	case kindMessage:
		return e.IsStreaming
	case kindToolCall:
		return e.Status == statusPending
	default:
		return false
	}
}

// isAssistant applies the app's role-derivation rule.
func (e transcriptEntry) isAssistant() bool {
	switch e.Kind {
	case kindSendMessage:
		return true
	case kindMessage:
		if len(e.FromAgent) > 0 && string(e.FromAgent) != "null" {
			return true
		}
		if len(e.FromUser) > 0 && string(e.FromUser) != "null" {
			return true
		}
		return e.Role == roleAssistant
	default:
		return false
	}
}

// Entry kinds and the few literal field values we branch on.
const (
	kindMessage        = "message"
	kindSendMessage    = "send-message"
	kindToolCall       = "tool-call"
	kindUserAttachment = "user-attachment"
	kindNotice         = "notice"
	kindEvent          = "event"
	kindFeedback       = "feedback"
	kindVoiceCall      = "voice-call"

	roleUser      = "user"
	roleAssistant = "assistant"

	statusPending = "pending"
	statusFailed  = "failed"

	msgTypeText = "text"
)
