package cloudsession

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Trigger is why a flush was called.
type Trigger string

// The flush triggers. Live grounding (CA-A2) saw SessionStart,
// UserPromptSubmit, PreToolUse and PostToolUse fire from repository hooks in
// a Claude Code cloud session, but never Stop or SessionEnd, so the cadence
// is carried by start, prompt and periodic; final is a bonus.
const (
	// TriggerStart is a SessionStart / sessionStart flush: always runs. It
	// ships what an earlier session in the same VM left behind, records the
	// session's hook-block baseline (guard.go) and probes the destination
	// early, so a network-level block shows up before any work is done.
	TriggerStart Trigger = "start"
	// TriggerPrompt is a UserPromptSubmit / userPromptSubmitted flush:
	// always runs, so each finished turn ships before the next starts.
	TriggerPrompt Trigger = "prompt"
	// TriggerPeriodic is a PostToolUse flush: runs on every Nth call so a
	// long autonomous turn ships while it runs.
	TriggerPeriodic Trigger = "periodic"
	// TriggerFinal is a Stop / SessionEnd / agentStop flush: always runs
	// when the vendor fires it, which is not guaranteed. The sandbox may be
	// torn down right after it, so coverage reads "partial history" until a
	// later flush confirms.
	TriggerFinal Trigger = "final"
)

// DefaultFlushEvery is the periodic cadence when none is configured.
const DefaultFlushEvery = 25

// TriggerSpec is one row of the trigger table: how a trigger behaves.
type TriggerSpec struct {
	Trigger Trigger
	// Periodic counts calls and runs on every Nth.
	Periodic bool
	// StartsSession marks the session's first hook: for an agent with no
	// vendor session reference it re-records the hook-block baseline
	// (guard.go), since nothing else tells one session from the next. With
	// a reference, a baseline for the same session is always kept (a
	// resumed or compacted session fires SessionStart again).
	StartsSession bool
	// SkipWhenBlocked skips the delivery (the scan still runs) while the
	// recorded coverage says the environment's network level blocks the
	// destination host for this session: retrying on every prompt or tool
	// call would only repeat a refusal the environment owner must fix.
	SkipWhenBlocked bool
	// ReportsMisconfig turns a misconfiguration (no destination, no ship
	// token, uncommitted hooks) into a failing exit, which the vendor shows
	// as a non-blocking hook error. Only the once-per-session trigger does,
	// so a broken setup is visible once instead of on every prompt; the
	// others record it in the coverage state and exit 0.
	ReportsMisconfig bool
	// Budget bounds the whole flush when --timeout is not given.
	Budget time.Duration
	// HookTimeoutSeconds is the vendor timeout written on the committed
	// hook entry: the budget plus margin for start-up and the scan.
	HookTimeoutSeconds int
}

// triggers is THE trigger table.
var triggers = []TriggerSpec{
	{Trigger: TriggerStart, StartsSession: true, ReportsMisconfig: true, Budget: 30 * time.Second, HookTimeoutSeconds: 60},
	{Trigger: TriggerPrompt, SkipWhenBlocked: true, Budget: 20 * time.Second, HookTimeoutSeconds: 30},
	{Trigger: TriggerPeriodic, Periodic: true, SkipWhenBlocked: true, Budget: 45 * time.Second, HookTimeoutSeconds: 60},
	{Trigger: TriggerFinal, Budget: 45 * time.Second, HookTimeoutSeconds: 60},
}

// Triggers returns every trigger, in table order.
func Triggers() []Trigger {
	out := make([]Trigger, len(triggers))
	for i, r := range triggers {
		out[i] = r.Trigger
	}
	return out
}

// TriggerSpecFor returns the trigger table row for t.
func TriggerSpecFor(t Trigger) (TriggerSpec, error) {
	for _, r := range triggers {
		if r.Trigger == t {
			return r, nil
		}
	}
	return TriggerSpec{}, fmt.Errorf("cloudsession: unknown trigger %q (want one of %v)", t, Triggers())
}

// FlushDecision is the outcome of ShouldFlush.
type FlushDecision struct {
	// Run reports whether this call flushes.
	Run bool
	// Counted reports whether the call advanced the periodic counter (the
	// caller persists Count).
	Counted bool
	// Count is the counter value after this call.
	Count int
}

// ShouldFlush decides whether this call flushes. prevCount is the persisted
// periodic counter; every <= 0 means DefaultFlushEvery.
func ShouldFlush(trigger Trigger, prevCount, every int) (FlushDecision, error) {
	r, err := TriggerSpecFor(trigger)
	if err != nil {
		return FlushDecision{}, err
	}
	if !r.Periodic {
		return FlushDecision{Run: true, Count: prevCount}, nil
	}
	if every <= 0 {
		every = DefaultFlushEvery
	}
	n := prevCount + 1
	if n < 0 { // overflow guard on a corrupt counter
		n = 1
	}
	return FlushDecision{Run: n%every == 0, Counted: true, Count: n}, nil
}

// DestinationKind is where a flush delivers the envelope.
type DestinationKind string

// The destination kinds.
const (
	// DestOrg is the org server's ship-token route (lane CA-B3 builds it).
	DestOrg DestinationKind = "org"
	// DestNode is the user's own reachable node (lane CA-B3 builds it).
	DestNode DestinationKind = "node"
	// DestFile writes each envelope to a local directory: tests, and a
	// dry look at exactly what would ship.
	DestFile DestinationKind = "file"
)

// destRule is one row of the destination table.
type destRule struct {
	kind DestinationKind
	// route is the path appended to the base URL (network kinds only).
	route string
	// network: the destination is an HTTPS endpoint reached through
	// internal/cloudsessionnet; otherwise it is a local directory.
	network bool
	// needsToken: the destination requires a ship token (CA-D8).
	needsToken bool
	// defaultShare is the share posture a flush to this destination takes
	// when none is given (decision CA-D19): the user's own node receives
	// full content by default (it is the owner's own data); the org and the
	// file destination default to metadata only, and the org posture is the
	// one the org server derived from the member's enrolment and returned at
	// mint, baked in by `init --share`.
	defaultShare SharePosture
}

// destinations is THE destination table.
var destinations = []destRule{
	{kind: DestOrg, route: "/ingest/cloud-session/v1/batch", network: true, needsToken: true, defaultShare: ShareMetadataOnly},
	{kind: DestNode, route: "/api/cloud-session/ingest", network: true, needsToken: true, defaultShare: ShareFullContent},
	{kind: DestFile, defaultShare: ShareMetadataOnly},
}

// SharePosture is what a flush ships (decision CA-D19). The spellings are the
// org server's (internal/shiptoken.Posture*), so the posture a mint response
// names is the value `init --share` takes; a cmd test pins the two equal.
type SharePosture string

// The share postures.
const (
	// ShareFullContent ships the raw content columns (the managed member's
	// node posture; the node destination's default).
	ShareFullContent SharePosture = "full_content"
	// ShareMetadataOnly ships hashes and metadata only.
	ShareMetadataOnly SharePosture = "metadata_only"
)

// SharePostures returns the accepted --share values.
func SharePostures() []SharePosture { return []SharePosture{ShareFullContent, ShareMetadataOnly} }

// ResolveShare returns the posture a flush to kind ships: requested when it
// is set (it must be a known posture), else the destination's default.
func ResolveShare(kind DestinationKind, requested SharePosture) (SharePosture, error) {
	for _, r := range destinations {
		if r.kind != kind {
			continue
		}
		switch requested {
		case "":
			return r.defaultShare, nil
		case ShareFullContent, ShareMetadataOnly:
			return requested, nil
		default:
			return "", fmt.Errorf("cloudsession: --share must be %s or %s, got %q", ShareFullContent, ShareMetadataOnly, requested)
		}
	}
	return "", fmt.Errorf("cloudsession: unknown destination %q", kind)
}

// DestinationKinds returns every destination kind, in table order.
func DestinationKinds() []DestinationKind {
	out := make([]DestinationKind, len(destinations))
	for i, r := range destinations {
		out[i] = r.kind
	}
	return out
}

// Destination is a resolved delivery target.
type Destination struct {
	Kind DestinationKind
	// Endpoint is the full URL a network destination POSTs to.
	Endpoint string
	// Dir is the directory a file destination writes into.
	Dir string
	// Network reports an HTTPS destination.
	Network bool
	// NeedsToken reports that a ship token is required.
	NeedsToken bool
}

// ResolveDestination turns a kind and its target (a base URL for a network
// kind, a directory for the file kind) into a Destination. A network base URL
// must be https, except plain http to a loopback host (a node on the same
// machine, and tests); it may not carry credentials, a query or a fragment.
func ResolveDestination(kind DestinationKind, target string) (Destination, error) {
	for _, r := range destinations {
		if r.kind != kind {
			continue
		}
		d := Destination{Kind: kind, Network: r.network, NeedsToken: r.needsToken}
		target = strings.TrimSpace(target)
		if target == "" {
			return Destination{}, fmt.Errorf("cloudsession: the %s destination needs a target (%s)", kind, targetHint(r))
		}
		if !r.network {
			d.Dir = target
			return d, nil
		}
		u, err := url.Parse(target)
		if err != nil {
			return Destination{}, fmt.Errorf("cloudsession: destination URL: %w", err)
		}
		switch {
		case u.User != nil:
			return Destination{}, fmt.Errorf("cloudsession: destination URL may not carry credentials; pass the ship token separately")
		case u.RawQuery != "" || u.Fragment != "":
			return Destination{}, fmt.Errorf("cloudsession: destination URL may not carry a query or fragment")
		case u.Host == "":
			return Destination{}, fmt.Errorf("cloudsession: destination URL %q has no host", target)
		case u.Scheme == "https":
		case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		default:
			return Destination{}, fmt.Errorf("cloudsession: destination URL must be https (plain http only to a loopback host), got %q", u.Scheme)
		}
		u.Path = strings.TrimRight(u.Path, "/") + r.route
		d.Endpoint = u.String()
		return d, nil
	}
	return Destination{}, fmt.Errorf("cloudsession: unknown destination %q (want one of %v)", kind, DestinationKinds())
}

func targetHint(r destRule) string {
	if r.network {
		return "a base URL, from --url or SBO_CLOUD_SESSION_URL"
	}
	return "a directory, from --url or SBO_CLOUD_SESSION_URL"
}

// isLoopbackHost reports the name "localhost" or a loopback IP literal with
// no zone. It is the same rule internal/cloudsessionnet's checkEndpoint
// applies at delivery (TestLoopbackRuleAgreesWithDelivery there), so init
// never accepts a destination the flush then refuses: a name that merely
// starts "127." (127.attacker.example) is not a literal and is refused.
func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.Zone() == "" && a.IsLoopback()
}

// Receipt is what a delivery reports back.
type Receipt struct {
	// Status is the HTTP status (0 for a file destination).
	Status int
	// Location is where a file destination wrote the envelope.
	Location string
	// Accepted is the server's accepted-row count when it reports one.
	Accepted int
}

// Deliverer sends one encoded envelope to a destination. The HTTP
// implementation lives in internal/cloudsessionnet (the feature's only
// egress package); so does the file implementation, so every delivery goes
// through one package.
type Deliverer interface {
	Deliver(ctx context.Context, envelope []byte) (Receipt, error)
}
