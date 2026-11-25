package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// parseRetryAfter reads a Retry-After header (delay-seconds or an HTTP-date)
// and returns the wait it asks for, clamped to [0, maxBackoff] so a hostile
// or broken server cannot park a node for longer than the ladder's own cap.
// An absent or unparseable header is 0 (no hint).
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxBackoff)
}

// retryAfterOf extracts the server's Retry-After hint from a push error.
func retryAfterOf(err error) time.Duration {
	var hs *httpStatusError
	if errors.As(err, &hs) {
		return hs.retryAfter
	}
	return 0
}

// failureDeduper tracks whether the CURRENT failure in a retry loop is new
// or a repeat of the immediately-preceding one, so a wedged remote (a dead
// org server, a persistent 5xx, ...) logs ONE WARN naming the remedy
// instead of one WARN per retry forever. That was the actual 2026-09-07
// complaint: a dev box enrolled against a now-dead localhost:8443 org
// server logged 316 WARN lines in the first hour after every restart.
//
// Pure and stateful, no I/O of its own — see warnOnce for the logging
// policy built on top of it. A caller owns one failureDeduper PER
// independent failure stream it wants deduplicated (e.g. one for the
// generic push failure, a separate one for auth failures, since those
// already run on separate backoff tracks) and must call observe("") on
// every cycle that did NOT fail, so a later failure — even one identical
// to the last — is treated as fresh and re-WARNs (a recovery re-arms it).
type failureDeduper struct {
	// lastKind is normalizeFailureKey(err) for the most recent failure
	// this deduper has seen, or "" if the tracker is currently clear
	// (either nothing has failed yet, or the last observed cycle
	// succeeded). Deliberately NOT err.Error(): the raw message embeds
	// variable payload (a server-echoed request id, a decode error's
	// byte offset, an OS-specific syscall rendering) that would compare
	// unequal between two occurrences of the SAME class of failure and
	// re-arm a WARN every single cycle — the exact bug class this type
	// exists to prevent, just one level down.
	lastKind string
	// repeats counts consecutive identical failures, INCLUDING the
	// current one — so the first sighting of a kind reports 1, not 0.
	repeats int
	// lastWarnAt is when warnOnce last actually emitted a WARN (zero
	// until the first one). It backstops a normalization gap: a failure
	// whose key keeps changing every cycle (because normalizeFailureKey
	// hasn't learned to collapse whatever varies in it) must still
	// degrade to "at most one WARN every warnBackstopInterval", not fall
	// back to per-cycle spam.
	lastWarnAt time.Time
}

// observe records one cycle's outcome. kind == "" means the cycle did NOT
// fail (success, or not applicable) and always clears the tracker. A
// non-empty kind identical to the previous failing cycle's kind is a
// REPEAT; a changed kind, or the first failure after a clear/success, is
// NOT a repeat (it deserves a fresh WARN, subject to warnOnce's time
// backstop). Returns (isRepeat, repeats).
func (d *failureDeduper) observe(kind string) (isRepeat bool, repeats int) {
	if kind == "" {
		d.lastKind = ""
		d.repeats = 0
		return false, 0
	}
	if kind == d.lastKind {
		d.repeats++
		return true, d.repeats
	}
	d.lastKind = kind
	d.repeats = 1
	return false, 1
}

// warnBackstopInterval bounds how often warnOnce will emit a fresh WARN
// even when the dedup key changes every cycle. It exists for the case
// normalizeFailureKey does NOT fully solve: a class of failure whose
// message keeps mutating in a way the normalizer hasn't learned to
// collapse. Without this, that gap would regress all the way back to
// one WARN per retry — the original 316-lines-an-hour complaint — just
// gated on a subtler trigger. clockNow is swappable in tests.
const warnBackstopInterval = 10 * time.Minute

var clockNow = time.Now

// warnOnce logs err through d: the FIRST sighting of a given failure kind
// (by normalizeFailureKey(err), not the raw message — see failureDeduper's
// doc comment) — including a CHANGED kind, or the first failure after a
// recovery — logs at WARN with msg and args, UNLESS the previous WARN from
// this same deduper landed less than warnBackstopInterval ago, in which
// case it too logs at DEBUG (the time backstop). Every IDENTICAL repeat of
// the immediately-preceding failure logs at DEBUG instead, tagged with a
// running "repeat_count" so the operator can still tell how long it's been
// going without one line per cycle. Callers must clear d (d.observe(""))
// on a successful cycle so the next failure — even an identical one —
// gets a fresh WARN.
func warnOnce(logger *slog.Logger, d *failureDeduper, err error, msg string, args ...any) {
	isRepeat, repeats := d.observe(normalizeFailureKey(err))
	fields := append(append([]any{}, args...), "err", err)
	if isRepeat {
		logger.Debug(msg+" (repeat, suppressed to DEBUG - see the first WARN for the remedy)", append(fields, "repeat_count", repeats)...)
		return
	}
	now := clockNow()
	if !d.lastWarnAt.IsZero() && now.Sub(d.lastWarnAt) < warnBackstopInterval {
		logger.Debug(msg+" (dedup key changed but within the WARN backstop window - suppressed to DEBUG)", fields...)
		return
	}
	d.lastWarnAt = now
	logger.Warn(msg, fields...)
}

// benignRailFetchStates is the closed set of org policy-distribution
// fetch-states that mean "the org deliberately isn't distributing this, or
// this node isn't asking" — an EXPECTED steady state, never an error.
//
// The three policy rails that ride the push loop (budget, pricing, intel)
// share their fetch-state string VALUES — orgcontract.BudgetFetch* (budgetposture.go),
// orgcontract.PricingFetch* (pricingpolicy.go), and the IntelFetch* set in
// intelrail.go all spell "channel_off", "disabled", etc. identically — so one
// table classifies all three call sites (CLAUDE.md #5: a data table, not a
// per-rail conditional). Each distinct value appears ONCE (a map literal can't
// repeat a key), referenced through whichever rail's constant defines it.
var benignRailFetchStates = map[string]bool{
	// 409: the org published no [policy] signing key, so the rail cannot serve
	// a trustworthy body. The documented, common opt-out state — not a failure.
	orgcontract.BudgetFetchChannelOff: true, // "channel_off" (all three rails)
	// [guard.budget].from_org / [intelligence].org_enrichment is off, so the
	// node never made the request. It isn't asking; nothing is wrong.
	orgcontract.BudgetFetchDisabled: true, // "disabled" (all three rails)
	// 404 on the pricing/intel rails: the org server predates the rail. An
	// opt-out by not-yet-deploying, not an error, and it clears nothing.
	orgcontract.PricingFetchNotSupported: true, // "not_supported" (pricing, intel)
	// 404 on the budget rail with nothing cached: the server governs no budget
	// for this caller. Never a failure, and never a clear (D-016).
	orgcontract.BudgetFetchNoBudget: true, // "no_budget" (budget)
	// a VERIFIED empty pricing body: the org negotiated nothing and the fleet
	// prices at seed. Deliberate, and produces no error anyway.
	orgcontract.PricingFetchNoPricing: true, // "no_pricing" (pricing)
	// no org enrolment on this node. Already excluded upstream by ErrNotEnrolled
	// at every call site; listed so the predicate is total, never as a gap.
	orgcontract.BudgetFetchNotEnrolled: true, // "not_enrolled" (all three rails)
}

// benignRailFetchState reports whether a policy-rail fetch-state is an expected
// steady state rather than a genuine problem, so the push loop can log budget /
// pricing / intel fetch failures in those states at Debug instead of a WARN per
// rail per cycle forever (the d67768ce5 regression: flipping
// [guard.budget].from_org on by default made every enrolled node poll rails a
// legitimately-unconfigured org answers 409 channel_off on).
//
// Everything NOT in the benign set stays at WARN. Two exclusions are
// deliberate. "unverified" is a signature-verification FAILURE (a served body
// this node could not check — security-relevant) and "auth_failed" is a refused
// credential; both are real. "unreachable" is a TRANSIENT network error, and it
// was a judgment call to leave it at WARN: a persistently-unreachable org is
// worth surfacing and self-resolves once the server returns, so a (deduped,
// backstopped) WARN is the better tradeoff than silence.
func benignRailFetchState(state string) bool {
	return benignRailFetchStates[state]
}

// logRailFetchFailure logs a non-nil policy-rail fetch outcome at the right
// level: Debug with debugMsg when the state is a benign steady state
// (benignRailFetchState), Warn with warnMsg otherwise. It lives here rather
// than inline at the three push-loop call sites so each site stays one
// statement — the level split would otherwise grow PushLoop's branch count for
// no behavioural reason. Callers still gate on err != nil (and exclude
// ErrNotEnrolled / context.Canceled) before calling.
func (c *Client) logRailFetchFailure(state, debugMsg, warnMsg string, err error) {
	if benignRailFetchState(state) {
		c.logger.Debug(debugMsg, "state", state, "err", err)
		return
	}
	c.logger.Warn(warnMsg, "state", state, "err", err)
}

// httpStatusError carries an HTTP status code separately from the
// (often server-controlled, and frequently variable — a request id, a
// timestamp) response body text, so normalizeFailureKey can key on the
// STATUS alone via errors.As instead of the full rendered message, which
// would otherwise re-arm a WARN every cycle the server's error body
// varies even slightly.
type httpStatusError struct {
	op     string
	status int
	body   string
	// retryAfter is the server's Retry-After hint (0 when absent). The push
	// loop waits at least this long before the next attempt, so a server
	// shedding load (503 log_full when its durable log is at its byte cap,
	// T-823) is not hammered by the fast first steps of the backoff ladder.
	retryAfter time.Duration
}

func (e *httpStatusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("%s: server returned %d", e.op, e.status)
	}
	return fmt.Sprintf("%s: server returned %d: %s", e.op, e.status, e.body)
}

// longDigitRun matches a run of 4+ consecutive digits — long enough to
// catch a request id, a unix timestamp, or a byte offset, short enough to
// leave a 1-3 digit HTTP status code embedded in prose (e.g. "returned
// 503") untouched.
var longDigitRun = regexp.MustCompile(`\d{4,}`)

// maxFailureKeyMsgLen bounds the fallback message tier of
// normalizeFailureKey so an unusually long error string doesn't grow the
// dedup key without bound.
const maxFailureKeyMsgLen = 120

// normalizeFailureKey derives failureDeduper's comparison key from err,
// collapsing variable payload that would otherwise make two occurrences
// of the SAME class of failure compare as different and re-arm a WARN
// every cycle. Three tiers, most to least specific:
//
//  1. A *url.Error — the shape net/http.Client wraps every transport
//     failure in — keys on Op plus a coarse network-error CLASS via
//     errors.Is/errors.As (timeout vs connection-refused vs "other"),
//     never the message text, which can carry a resolved address or an
//     OS-specific syscall rendering that varies harmlessly between
//     attempts while the underlying class does not.
//  2. An *httpStatusError (see PushOnce) keys on the status code alone —
//     never the echoed response body, which is exactly the variable
//     payload this function exists to strip. A genuine status change
//     (500 → 503) DOES yield a different key: that is an
//     operator-meaningful change, not noise.
//  3. Anything else falls back to the first maxFailureKeyMsgLen bytes of
//     the message with digit runs of 4+ collapsed to a single '#' (see
//     longDigitRun) — long enough to catch a request id / unix
//     timestamp / byte offset, short enough to leave a short HTTP status
//     embedded in prose untouched.
func normalizeFailureKey(err error) string {
	if err == nil {
		return ""
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return "net:" + uerr.Op + ":" + classifyNetError(uerr.Err)
	}
	var serr *httpStatusError
	if errors.As(err, &serr) {
		return fmt.Sprintf("status:%d", serr.status)
	}
	msg := err.Error()
	if len(msg) > maxFailureKeyMsgLen {
		msg = msg[:maxFailureKeyMsgLen]
	}
	return "msg:" + longDigitRun.ReplaceAllString(msg, "#")
}

// classifyNetError buckets a *url.Error's wrapped cause into a coarse,
// stable class (timeout / connection-refused / connection-reset / other)
// via errors.Is/errors.As rather than string matching, so an OS-specific
// rendering of the same syscall never produces a different class.
func classifyNetError(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "conn-refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "conn-reset"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "timeout"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "timeout"
		}
		return "other"
	}
}

// authFailure is the ADDITIVE discriminator half of a 401/403 body. Both fields
// are absent from a v1.8-class server's response, so every consumer must treat
// the zero value as "the server did not say".
type authFailure struct {
	Reason              string `json:"reason"`
	BoundKeyFingerprint string `json:"bound_key_fingerprint"`
}

// parseAuthFailure extracts the discriminator from an error body. A body that
// carries none (an older server, or a proxy's own error page) yields the zero
// value rather than an error: this is diagnosis, and failing to diagnose must
// never change the outcome of the push.
func parseAuthFailure(body []byte) authFailure {
	var f authFailure
	if err := json.Unmarshal(body, &f); err != nil {
		return authFailure{}
	}
	return f
}

// reportAuthFailure logs WHY a push was rejected and returns the message string
// recorded against the push (and shown by `observer org status`).
//
// Before this, a stranded node reported only "unauthorized: invalid per-push
// signature" — indistinguishable from a clock skew, a revoked bearer, or the
// key-binding collision that actually caused the 2026-08-26/27 incident, where
// a second machine enrolling under the same org member silently took over the
// binding and left this node 401ing forever.
//
// Two sources are combined. The server's `reason` is authoritative when
// present. Independently, comparing our own key fingerprint against the
// `bound_key_fingerprint` the server reports proves a binding conflict LOCALLY
// — which is what lets a current agent diagnose the collision even against a
// server too old to name it.
func (c *Client) reportAuthFailure(body []byte, status int, localFP, orgURL string) string {
	msg := serverError(body, status)
	f := parseAuthFailure(body)

	reason := f.Reason
	// The local proof outranks a server that could only say "the signature did
	// not verify": if the server holds a DIFFERENT key than ours, the cause is
	// not a bad signature, it is a displaced binding.
	if f.BoundKeyFingerprint != "" && localFP != "" && f.BoundKeyFingerprint != localFP &&
		(reason == "" || reason == orgcontract.AuthReasonSignatureMismatch) {
		reason = orgcontract.AuthReasonBindingConflict
	}

	attrs := []any{
		"status", status,
		"detail", msg,
		"org_server", orgURL,
		"local_key_fingerprint", localFP,
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	if f.BoundKeyFingerprint != "" {
		attrs = append(attrs, "server_bound_key_fingerprint", f.BoundKeyFingerprint)
	}
	if remedy := authFailureRemedy(reason); remedy != "" {
		attrs = append(attrs, "remedy", remedy)
	}
	c.logger.Warn("org push rejected", attrs...)

	if reason != "" {
		// Fold the reason into the RECORDED message too: `observer org status`
		// and the dashboard read this string, and they are where an operator
		// looks before they ever see a daemon log.
		return reason + ": " + msg
	}
	return msg
}

// authFailureRemedy maps a reason to the one action that resolves it. A table,
// not a conditional ladder (CLAUDE.md #5); an unknown reason yields "" so a
// future server-side reason never produces confidently wrong advice.
func authFailureRemedy(reason string) string {
	switch reason {
	case orgcontract.AuthReasonBindingConflict:
		return "another machine enrolled under this org member and took the key binding; re-enrol this node, or give each machine its own member"
	case orgcontract.AuthReasonUnknownKey:
		return "no agent key is bound for this member; re-enrol this node"
	case orgcontract.AuthReasonTimestampSkew:
		return "this host's clock is outside the server's allowed skew; sync time"
	case orgcontract.AuthReasonMissingSignature, orgcontract.AuthReasonMalformedSignature:
		return "the per-push signature headers did not reach the server intact; check for an intermediate proxy stripping X-SBO-* headers"
	case orgcontract.AuthReasonSignatureMismatch:
		return "the signature did not verify against the bound key; re-enrol this node if it persists"
	default:
		return ""
	}
}

// serverError renders a concise error string from a JSON error body, falling
// back to the status code when the body is empty/unparseable.
func serverError(body []byte, status int) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		if e.Message != "" {
			return e.Error + ": " + e.Message
		}
		return e.Error
	}
	if s := strings.TrimSpace(string(body)); s != "" {
		return s
	}
	return http.StatusText(status)
}
