package cloudagents

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cline"
)

// Cline Cloud Agents (lane CA-V6, connector cline-cloud). The session API on
// api.cline.bot is undocumented: the connector carries the grounding level
// "Observed in vendor client, undocumented" (grounding.go) and reads the
// three pure drivers of internal/vendorapi/cline. Spec: the Cline section of
// docs/plans/cloud-agents/grounding/wave-c-vendors-2026-11-01.md.

// ConnectorClineCloud is the Cline Cloud Agents connector id.
const ConnectorClineCloud = "cline-cloud"

// SurfaceHostClineCloud is the surface host of a pulled Cline cloud session
// (CA-D15): tool "cline" stays, the product is told apart by this host. It
// is in orgpush.go's knownSurfaceHosts.
const SurfaceHostClineCloud = "cline-cloud"

// DetailStatus reads one session's status (Cline: GET
// /api/v1/session/{id}/status).
const DetailStatus DetailKind = "status"

// ClineStatusExpired is the vendor status a Cline session is given once its
// expiredAt has passed: the vendor's own client derives "expired" from that
// time before it looks at the record's status
// (sdk-cloud-session-coordinator.ts statusOf), and maps it to "cancelled".
const ClineStatusExpired = "expired"

// clineStatuses maps a Cline cloud session's REST status to a lifecycle.
// "ready" and "active" are deliberately NOT rows: they only say the sandbox
// is up, and the vendor's own client states that REST "cannot tell a busy
// agent from an idle sandbox" (sdk-cloud-session-coordinator.ts), so they
// read as unknown (counted under OPEN) rather than a guessed running or
// idle. "suspended" is a resumable sandbox asleep after 15 idle minutes:
// waiting for the user.
var clineStatuses = map[string]Lifecycle{
	"provisioning":     LifecycleRunning,
	"pending":          LifecycleRunning,
	"suspended":        LifecycleWaiting,
	"failed":           LifecycleFailed,
	ClineStatusExpired: LifecycleCancelled,
}

// clineStatusDetails refine a status by the provisioning phase: a sandbox
// still provisioning whose phase is "failed" has failed.
var clineStatusDetails = []StatusDetailRule{
	{Status: "provisioning", Detail: "failed", Lifecycle: LifecycleFailed},
}

// mapClineSession reads the Cline parts of a session snapshot into t and
// returns the status and detail the lifecycle table maps, and the time the
// session ended when the vendor states one (its expiry). now is when the
// page was read.
func mapClineSession(b map[string]string, t *Task, now time.Time) (status, detail string, end time.Time) {
	t.RepoRemote = RemoteFromURL(b["repo_url"])
	if ref := b["task_id"]; ValidSessionID(ref) && ref != t.ID {
		t.VendorRef = ref
	}
	if src := b["handoff_source_session_id"]; ValidSessionID(src) && src != t.ID {
		t.ForkedFromID = src
	}
	status, detail = b["status"], b["provisioning_phase"]
	if exp := snapshotTime(b, "expired_at"); !exp.IsZero() && !exp.After(now) {
		status, end = ClineStatusExpired, exp
	}
	return status, detail, end
}

// applyClineStatus folds a status read into a task. An expired session
// stays expired (the vendor client's own order).
func applyClineStatus(c Connector, t Task, snaps []vendorapi.VendorSnapshot) Task {
	for _, s := range snaps {
		if s.Class != cline.StatusClass || s.Subject != t.ID || t.VendorStatus == ClineStatusExpired {
			continue
		}
		status := s.Body["status"]
		t.VendorStatus, t.Lifecycle = boundToken(status), c.LifecycleOfDetail(status, s.Body["phase"])
		t.CompletedAt = time.Time{}
		if t.Lifecycle.Terminal() {
			t.CompletedAt = t.UpdatedAt
		}
	}
	return t
}

// clineHistoryFigures maps a Cline history usage row (the session's summed
// message metrics) to a token figure and a US-dollar figure. A row carries
// tokens only when a message reported a count, and a cost only when a
// message reported one; absent stays absent, never zero (CA-D11).
func clineHistoryFigures(u vendorapi.UsageRow) (*TokenFigure, []UsageFigure) {
	var tok *TokenFigure
	if u.Flags[cline.TokensFlag] == "true" {
		// metrics.inputTokens is GROSS: it includes the cache reads (live
		// check 2026-11-02: fitting the per-message metrics.cost to the
		// token split gives sensible prices only when input includes
		// cacheReadTokens, and a negative cached price when it is read as
		// net; cacheReadTokens sat just below inputTokens on every message).
		// It is netted the way the OpenHands mapping nets its prompt total,
		// never below zero. Whether it also includes cache writes is not
		// observed (cacheWriteTokens was 0 on every live message), so
		// cacheWriteTokens is carried as reported and not subtracted.
		tok = &TokenFigure{
			Kind: TokenFromProviderRunTotal, Model: boundField(u.Model),
			Input: netInput(u.InputTokens, u.CacheReadTokens), Output: u.OutputTokens, CacheRead: u.CacheReadTokens,
			CacheCreation: u.CacheWriteTokens, ReportedAt: u.At,
		}
	}
	var usage []UsageFigure
	if u.ChargedUnit == cline.ChargedUnitUSD {
		// Cline credits are US dollars; the figure is the vendor-reported
		// cost summed over the archived messages, a running total.
		usage = append(usage, UsageFigure{
			Unit: "usd", Value: float64(u.ChargedMicros) / 1e6, ValueType: models.UsageValueCumulative,
			Source: models.UsageSourceProviderRunTotal, MonetaryStatus: models.UsageMonetaryReported,
			ReportedAt: u.At, Model: boundField(u.Model),
		})
	}
	return tok, usage
}
