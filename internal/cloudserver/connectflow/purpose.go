package connectflow

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// purpose.go holds the second purpose of a connect request (the AI Apps SDK
// quickstart's device sign-in, docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md
// section 3.6; docs/security.md SDKQS-1): `npx @superbased/sdk setup` or
// `uvx superbased-sdk setup` asks for the member's own SDK key, the person
// approves it on the same page as a machine, and the poll hands the SDK a
// signed key grant its organization's host redeems.
//
// What a request is for, how its poll proves itself, which browser answers
// it takes and what an approved poll hands over are capabilities of the
// request, one row per purpose in purposeRows; callers read the row, never
// the purpose's name.

// Purpose is what a connect request is for.
type Purpose string

// Purposes.
const (
	// PurposeMachine is `observer connect`: sign a machine in and connect it
	// to a dashboard (the flow of 0150).
	PurposeMachine Purpose = "machine"
	// PurposeSDKKey is the SDK setup's device sign-in: mint the member's own
	// SDK key on the chosen dashboard.
	PurposeSDKKey Purpose = "sdk_key"
)

// AuthKind is how a poll proves it comes from the requester.
type AuthKind string

// Auth kinds.
const (
	// AuthPoP is the machine's Ed25519 proof of possession of the key it sent
	// at create (the SBO-PoP header).
	AuthPoP AuthKind = "pop"
	// AuthDeviceCode is a bearer device code: 256 random bits returned once
	// by the create, stored as its SHA-256, compared in constant time
	// (RFC 8628's model). The SDKs' setup uses it because Python's standard
	// library has no Ed25519.
	AuthDeviceCode AuthKind = "device_code"
)

// Answer is what an approved request's delivering poll hands over.
type Answer string

// Answers.
const (
	// AnswerSignIn is the machine's device sign-in (and, with a target, the
	// one-step attach grant).
	AnswerSignIn Answer = "sign_in"
	// AnswerKeyGrant is the signed SDK key grant; never a cloud sign-in, so
	// no cloud API token ever reaches an SDK.
	AnswerKeyGrant Answer = "key_grant"
)

// purposeRow is one purpose's capabilities.
type purposeRow struct {
	purpose Purpose
	// auth is how its polls prove themselves.
	auth AuthKind
	// create is its create body's rule table.
	create []fieldRule
	// events are the browser answers it takes (an SDK key has no "Not now":
	// there is no sign-in without a dashboard to hand over).
	events []Event
	// answer is what an approved, delivering poll hands over.
	answer Answer
	// disclosure renders what the approval page shows for one dashboard.
	disclosure func(kind DashboardKind, name string) (DisclosureText, bool)
}

// purposeRows is one row per purpose. An empty purpose on the wire is a
// machine (every client before the SDK purpose sends none).
var purposeRows = []purposeRow{
	{
		purpose: PurposeMachine, auth: AuthPoP, create: machineCreateRules,
		events:     []Event{EventConnect, EventNotNow, EventDecline},
		answer:     AnswerSignIn,
		disclosure: machineDisclosure,
	},
	{
		purpose: PurposeSDKKey, auth: AuthDeviceCode, create: sdkKeyCreateRules,
		events:     []Event{EventConnect, EventDecline},
		answer:     AnswerKeyGrant,
		disclosure: SDKKeyDisclosure,
	},
}

// purposeRowFor returns the row of p ("" reads as PurposeMachine).
func purposeRowFor(p Purpose) (purposeRow, bool) {
	if p == "" {
		p = PurposeMachine
	}
	for _, r := range purposeRows {
		if r.purpose == p {
			return r, true
		}
	}
	return purposeRow{}, false
}

// ParsePurpose reads a stored or sent purpose ("" is PurposeMachine); ok is
// false for an unknown one.
func ParsePurpose(s string) (Purpose, bool) {
	r, ok := purposeRowFor(Purpose(s))
	return r.purpose, ok
}

// AuthFor is the auth kind of a purpose's polls. An unknown purpose has
// none ("", false): its poll is refused.
func AuthFor(p Purpose) (AuthKind, bool) {
	r, ok := purposeRowFor(p)
	return r.auth, ok
}

// AnswerFor is what an approved, delivering poll of a purpose hands over.
func AnswerFor(p Purpose) (Answer, bool) {
	r, ok := purposeRowFor(p)
	return r.answer, ok
}

// Allows reports whether a request of purpose p takes the browser answer ev.
func Allows(p Purpose, ev Event) bool {
	r, ok := purposeRowFor(p)
	if !ok {
		return false
	}
	for _, e := range r.events {
		if e == ev {
			return true
		}
	}
	return false
}

// DisclosureFor renders what the approval page shows for a dashboard of kind
// named name, for a request of purpose p. ok is false for an unknown purpose
// or kind.
func DisclosureFor(p Purpose, kind DashboardKind, name string) (DisclosureText, bool) {
	r, ok := purposeRowFor(p)
	if !ok {
		return DisclosureText{}, false
	}
	return r.disclosure(kind, name)
}

// machineDisclosure is a machine's disclosure: the share level the dashboard
// kind implies, and its text.
func machineDisclosure(kind DashboardKind, name string) (DisclosureText, bool) {
	level, ok := ShareLevelFor(kind)
	if !ok {
		return DisclosureText{}, false
	}
	return Disclosure(level, name)
}

// ---------------------------------------------------------------------------
// The device code
// ---------------------------------------------------------------------------

// DeviceCodeBytes is the device code's entropy: 256 bits.
const DeviceCodeBytes = 32

// maxDeviceCodeChars bounds a presented code before it is hashed (a real
// one is 43 characters).
const maxDeviceCodeChars = 128

// NewDeviceCode mints a device code from r (crypto/rand.Reader in
// production): DeviceCodeBytes random bytes, base64url without padding. It
// returns the code, which the create answers once, and its hash, which is all
// that is stored.
func NewDeviceCode(r io.Reader) (code, hash string, err error) {
	b := make([]byte, DeviceCodeBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", "", fmt.Errorf("connectflow.NewDeviceCode: %w", err)
	}
	code = base64.RawURLEncoding.EncodeToString(b)
	return code, DeviceCodeHash(code), nil
}

// DeviceCodeHash is the hex SHA-256 of a device code: what is stored.
func DeviceCodeHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// DeviceCodeMatches reports whether presented is the code whose hash is
// stored. The comparison is over the two hashes in constant time; an empty
// or oversized presentation, or an empty stored hash, never matches.
func DeviceCodeMatches(storedHash, presented string) bool {
	if storedHash == "" || presented == "" || len(presented) > maxDeviceCodeChars {
		return false
	}
	got := DeviceCodeHash(presented)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// BearerToken returns the token of an "Authorization: Bearer <token>" value,
// or "" when the header is not a bearer.
func BearerToken(header string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// ---------------------------------------------------------------------------
// The key grant's delivery
// ---------------------------------------------------------------------------

// KeyGrantPoll is the decision about one poll of an SDK key request.
type KeyGrantPoll string

// Key grant poll outcomes.
const (
	// KeyGrantNone: the request is not approved; nothing to hand over.
	KeyGrantNone KeyGrantPoll = "none"
	// KeyGrantNotReady: approved, but the chosen dashboard is not active yet
	// (a new account's personal dashboard being set up). The poll answers
	// approved with target.ready false and no grant; it does not count as a
	// delivery.
	KeyGrantNotReady KeyGrantPoll = "not_ready"
	// KeyGrantDeliver: hand the grant over (and count the delivery).
	KeyGrantDeliver KeyGrantPoll = "deliver"
	// KeyGrantExhausted: the grant was handed over as often as allowed, or
	// was handed over and the approval is now as old as allowed (409
	// key_grant_already_delivered).
	KeyGrantExhausted KeyGrantPoll = "exhausted"
	// KeyGrantWindowClosed: the approval is older than the delivery window
	// and no grant was ever handed over (a personal dashboard still being set
	// up the whole time; 409 key_grant_window_closed).
	KeyGrantWindowClosed KeyGrantPoll = "window_closed"
)

// KeyGrantFacts are the inputs of KeyGrantDecision.
type KeyGrantFacts struct {
	Status     Status
	Deliveries int
	ApprovedAt time.Time
	// TargetReady is true when the chosen dashboard is active (the cloud's
	// own org state).
	TargetReady bool
	Now         time.Time
}

// keyGrantRule is one row: the first whose when holds decides.
type keyGrantRule struct {
	id      string
	when    func(KeyGrantFacts) bool
	outcome KeyGrantPoll
}

// keyGrantRules decide what an SDK key poll receives, top down. They are the
// sign-in's delivery rules (MaxDeliveries, DeliveryWindow) with one more row:
// a dashboard that is not ready yet is waited for, inside the window, without
// using a delivery. The grant is anchored to the approval (issued at it, ten
// minutes of life), so past the window there is nothing valid to hand over;
// the answer then says whether a grant ever went out
// (sdk/contract/fixtures/setup/connect-poll.json already_delivered and
// window_closed).
var keyGrantRules = []keyGrantRule{
	{id: "not-approved", when: func(f KeyGrantFacts) bool { return f.Status != StatusApproved }, outcome: KeyGrantNone},
	{id: "too-many", when: func(f KeyGrantFacts) bool { return f.Deliveries >= MaxDeliveries }, outcome: KeyGrantExhausted},
	{id: "too-late, delivered", when: func(f KeyGrantFacts) bool {
		return f.Now.Sub(f.ApprovedAt) > DeliveryWindow && f.Deliveries > 0
	}, outcome: KeyGrantExhausted},
	{id: "too-late, never delivered", when: func(f KeyGrantFacts) bool { return f.Now.Sub(f.ApprovedAt) > DeliveryWindow }, outcome: KeyGrantWindowClosed},
	{id: "not-ready", when: func(f KeyGrantFacts) bool { return !f.TargetReady }, outcome: KeyGrantNotReady},
	{id: "deliver", when: func(KeyGrantFacts) bool { return true }, outcome: KeyGrantDeliver},
}

// KeyGrantDecision decides what one poll of an SDK key request receives.
func KeyGrantDecision(f KeyGrantFacts) KeyGrantPoll {
	for _, r := range keyGrantRules {
		if r.when(f) {
			return r.outcome
		}
	}
	return KeyGrantNone
}

// ---------------------------------------------------------------------------
// The SDK key's disclosure
// ---------------------------------------------------------------------------

// SDKKeyDisclosureVersion names the SDK key disclosure texts below. Change it
// whenever a text changes, so a consent receipt always names the words that
// were shown.
const SDKKeyDisclosureVersion = "sdk-key-disclosure.v1"

// dashboardMark is where the dashboard's name goes in an SDK key template.
const dashboardMark = "{dashboard}"

// SDKKeyLine is the key sentence the SDK docs use (plan section 1.3, G5):
// the SDK key is the only key traces need.
const SDKKeyLine = "Traces need this SDK key, and nothing else."

// sdkKeyTexts is the SDK key disclosure per dashboard kind, at
// SDKKeyDisclosureVersion: what the key can do, where it is kept, how long it
// lasts, how to end it, and the one thing a phished approval gives away.
var sdkKeyTexts = []struct {
	kind     DashboardKind
	title    string
	template string
}{
	{
		kind:  KindPersonal,
		title: "An SDK key for your personal dashboard",
		template: "Apps on that computer can use the key to send traces, logs and metrics to " + dashboardMark +
			", ask admission, read its prompts and trace costs, and write scores. " + SDKKeyLine + " " +
			"The key is kept in a file on that computer that only its user account can read, and is never shown. " +
			"It expires in 90 days; to end it sooner, run setup with --forget on that computer, " +
			"or revoke it on the dashboard's Machine identities page. " +
			"Approve only a request you started on your own computer: whoever holds the key can send data to " + dashboardMark +
			" and read its prompts until it is revoked.",
	},
	{
		kind:  KindTeam,
		title: "Your own SDK key on this team",
		template: "Apps on that computer can use the key to send traces, logs and metrics to " + dashboardMark +
			", ask admission, read its prompts and trace costs, and write scores. " + dashboardMark +
			"'s admins can read what your apps send, prompts and responses included. " + SDKKeyLine + " " +
			"The key is yours: it ends when you leave " + dashboardMark + ". " +
			"It is kept in a file on that computer that only its user account can read, and is never shown. " +
			"It expires in 90 days; to end it sooner, run setup with --forget on that computer, " +
			"or ask an admin of " + dashboardMark + " to revoke it. " +
			"Approve only a request you started on your own computer: whoever holds the key can send data to " + dashboardMark +
			" and read its prompts until it is revoked.",
	},
}

// personalDashboardName is the personal dashboard's name inside a sentence.
const personalDashboardName = "your personal dashboard"

// SDKKeyDisclosure renders the SDK key disclosure for a dashboard of kind
// named name; ok is false for an unknown kind. Its share level is the one
// the kind implies (a team's admins read in full), so the consent receipt
// records it like a machine's.
func SDKKeyDisclosure(kind DashboardKind, name string) (DisclosureText, bool) {
	level, ok := ShareLevelFor(kind)
	if !ok {
		return DisclosureText{}, false
	}
	dashboard := personalDashboardName
	if kind != KindPersonal {
		dashboard = CleanMachineName(name)
	}
	for _, d := range sdkKeyTexts {
		if d.kind != kind {
			continue
		}
		title := strings.ReplaceAll(d.title, dashboardMark, dashboard)
		text := strings.ReplaceAll(d.template, dashboardMark, dashboard)
		sum := sha256.Sum256([]byte(SDKKeyDisclosureVersion + "\n" + text))
		return DisclosureText{
			Level: level, Title: title, Text: text,
			Version: SDKKeyDisclosureVersion, SHA256: hex.EncodeToString(sum[:]),
		}, true
	}
	return DisclosureText{}, false
}
