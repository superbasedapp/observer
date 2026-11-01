package secfeed

import (
	"strings"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// OnlineStatus is what the online check said about one package.
type OnlineStatus string

// The online statuses.
const (
	// OnlineNotAsked: no online check ran (online checks off, the
	// disclosure not yet shown, a private or invalid name, a managed node
	// with no relay, the hook with no daemon to ask and a cache miss).
	OnlineNotAsked OnlineStatus = "not_asked"
	// OnlineAnswered: the source answered and the package exists.
	OnlineAnswered OnlineStatus = "answered"
	// OnlineNotFound: the registry says the package does not exist.
	OnlineNotFound OnlineStatus = "not_found"
	// OnlineFailed: asked, and no usable answer within the budget
	// (timeout, rate limit, DNS or TLS failure, a bad answer, the daemon
	// or the relay down). S-748.
	OnlineFailed OnlineStatus = "failed"
)

// OnlineAnswer is one package's online facts. It is the cache's record,
// the ask channel's answer and the relay's row, so the three cannot drift.
type OnlineAnswer struct {
	Eco     Ecosystem    `json:"eco"`
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	Status  OnlineStatus `json:"status"`
	// FirstPublished is the registry's first publish time (zero: unknown,
	// as in mirror mode).
	FirstPublished time.Time `json:"first_published,omitzero"`
	// MalIDs are OSV MAL- reports the online source returned. Only MAL-
	// ids are malicious; other advisories are VulnIDs (Phase D2's).
	MalIDs  []string `json:"mal_ids,omitempty"`
	VulnIDs []string `json:"vuln_ids,omitempty"`
	// MalAllVersions reports that one of MalIDs, read in full, covers every
	// version of the package (lane SEC-D1FIX2 milestone 2a): an unpinned
	// install of it is malicious (S-741), not "some versions" (S-749).
	MalAllVersions bool `json:"mal_all,omitempty"`
	// Private reports that the asked side classified the name private and
	// sent it nowhere (status not_asked).
	Private bool `json:"private,omitempty"`
	// Reason is a closed failure code for OnlineFailed.
	Reason    string    `json:"reason,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
}

// The reason codes a check records (InstallCheck.Reason). Closed: a surface
// may print them, and nothing repository-controlled reaches one.
const (
	ReasonListedOffline   = "listed_offline"
	ReasonListedOnline    = "listed_online"
	ReasonListedVersion   = "listed_some_versions"
	ReasonPopular         = "popular"
	ReasonNearMiss        = "near_miss"
	ReasonNotFound        = "registry_not_found"
	ReasonTooNew          = "too_new"
	ReasonExists          = "registry_exists"
	ReasonOnlineFailed    = "online_failed"
	ReasonIndexUnusable   = "index_unusable"
	ReasonPrivateOffline  = "private_offline_only"
	ReasonNotAsked        = "online_not_asked"
	ReasonInvalidLocation = "not_a_registry_name"
	// ReasonNotSetUp: no signed index was ever installed and online checks
	// are off or not yet disclosed, so nothing can check the package (the
	// hook notes it once per session, never on every install).
	ReasonNotSetUp = "not_set_up"
	// ReasonTooMany: the event names more packages than one check holds;
	// this check stands for the ones not checked online (Gate).
	ReasonTooMany = "too_many_packages"
)

// DecideInput is everything one package's verdict depends on.
type DecideInput struct {
	Spec InstallSpec
	// Private is the classifier's verdict: the name is never sent online.
	Private bool
	// Offline is the index's answer; IndexFreshness is how usable the
	// index is (content.Unknown means it cannot vouch for anything).
	Offline        Answer
	IndexFreshness content.Freshness
	Online         OnlineAnswer
	// MinAge is the minimum package age (too_new below it); 0 disables.
	MinAge time.Duration
	Now    time.Time
}

// decideRow is one row of the verdict table.
type decideRow struct {
	reason  string
	when    func(in DecideInput) bool
	verdict policy.InstallVerdict
	source  policy.InstallSource
}

// decideTable is THE verdict table, walked top-down; the first row that
// matches decides (section 8.3 "Outcomes"):
//
//   - an authenticated offline listing that covers the version installed
//     is malicious whatever the index's age (age weakens only an absent
//     listing), and no online answer can clear it (an online answer can
//     only raise a verdict);
//   - an online MAL- report for a pinned version is malicious too, and so is
//     one for an unpinned install when the report covers every version;
//   - a listing of some versions that an unpinned install (or a version
//     range) may resolve to is listed_version (S-749 flags), offline or
//     online: OSV answers an unpinned query with every version's reports;
//   - a popular name is known good; one edit from a popular name is a near
//     miss, unless the name is private (section 5.4);
//   - "does not exist" is unknown (S-744); a package younger than the
//     minimum age is too new (S-743); an existing, old enough package is
//     known good;
//   - an online check that was asked and did not answer is online_unknown
//     (S-748): the offline verdict above it already stood;
//   - a private name is decided by the offline index alone: nothing listed
//     means no verdict, also when the index cannot vouch (lane SEC-D1FIX2
//     milestone 2d: a private name can never be checked online, so an
//     unusable index does not flag S-744 on its every install; the index's
//     state shows on Code security and in the doctor);
//   - an index that cannot vouch (missing, past its age floor) with no
//     online answer is unknown (PR14);
//   - a public name with online checks off is decided by the offline index
//     alone: nothing listed means no verdict.
var decideTable = []decideRow{
	{ReasonInvalidLocation, func(in DecideInput) bool { return in.Spec.Invalid }, policy.InstallNotChecked, policy.InstallSourceNone},
	{ReasonListedOffline, func(in DecideInput) bool { return in.Offline.Malicious }, policy.InstallMalicious, policy.InstallSourceOffline},
	{ReasonListedOnline, func(in DecideInput) bool {
		return (in.Spec.Version != "" || in.Online.MalAllVersions) && in.Online.Status == OnlineAnswered && len(malOnly(in.Online.MalIDs)) > 0
	}, policy.InstallMalicious, policy.InstallSourceOnline},
	{ReasonListedVersion, func(in DecideInput) bool { return in.Offline.ListedVersions }, policy.InstallListedVersion, policy.InstallSourceOffline},
	{ReasonListedVersion, func(in DecideInput) bool {
		return in.Online.Status == OnlineAnswered && len(malOnly(in.Online.MalIDs)) > 0
	}, policy.InstallListedVersion, policy.InstallSourceOnline},
	{ReasonPopular, func(in DecideInput) bool { return in.Offline.Popular }, policy.InstallKnownGood, policy.InstallSourceOffline},
	{ReasonNearMiss, func(in DecideInput) bool { return in.Offline.NearMiss != "" && !in.Private }, policy.InstallNearMiss, policy.InstallSourceOffline},
	{ReasonNotFound, func(in DecideInput) bool { return in.Online.Status == OnlineNotFound }, policy.InstallUnknownName, policy.InstallSourceOnline},
	{ReasonTooNew, func(in DecideInput) bool {
		return in.Online.Status == OnlineAnswered && in.MinAge > 0 && !in.Online.FirstPublished.IsZero() &&
			in.Now.Sub(in.Online.FirstPublished) < in.MinAge
	}, policy.InstallTooNew, policy.InstallSourceOnline},
	{ReasonExists, func(in DecideInput) bool { return in.Online.Status == OnlineAnswered }, policy.InstallKnownGood, policy.InstallSourceOnline},
	{ReasonOnlineFailed, func(in DecideInput) bool { return in.Online.Status == OnlineFailed }, policy.InstallOnlineUnknown, policy.InstallSourceOnline},
	{ReasonPrivateOffline, func(in DecideInput) bool { return in.Private }, policy.InstallNotChecked, policy.InstallSourceOffline},
	{ReasonIndexUnusable, func(in DecideInput) bool {
		return in.IndexFreshness == content.Unknown || in.Offline.MaliciousMissing
	}, policy.InstallUnknownName, policy.InstallSourceOffline},
	{ReasonNotAsked, func(DecideInput) bool { return true }, policy.InstallNotChecked, policy.InstallSourceOffline},
}

// Decide returns one package's check.
func Decide(in DecideInput) policy.InstallCheck {
	if in.Online.Private {
		in.Private = true
	}
	c := policy.InstallCheck{
		Ecosystem: string(in.Spec.Eco), Name: SafeName(in.Spec.Name), Version: SafeName(in.Spec.Version), Private: in.Private,
	}
	if in.Spec.Invalid {
		c.Name = SafeName(in.Spec.Spec)
	}
	for _, r := range decideTable {
		if r.when(in) {
			c.Verdict, c.Source, c.Reason = r.verdict, r.source, r.reason
			if r.verdict == policy.InstallNearMiss {
				c.NearMiss = SafeName(in.Offline.NearMiss)
			}
			break
		}
	}
	return c
}

// Summarize returns the strongest verdict of checks and its source.
func Summarize(checks []policy.InstallCheck) (policy.InstallVerdict, policy.InstallSource) {
	v, s := policy.InstallNotChecked, policy.InstallSourceNone
	for _, c := range checks {
		if policy.InstallVerdictRank(c.Verdict) > policy.InstallVerdictRank(v) {
			v, s = c.Verdict, c.Source
		}
	}
	return v, s
}

func malOnly(ids []string) []string {
	var out []string
	for _, id := range ids {
		if strings.HasPrefix(id, "MAL-") {
			out = append(out, id)
		}
	}
	return out
}

// SafeName caps a package name at policy.InstallNameMax bytes and replaces
// anything outside printable ASCII with "?", so a name can reach deny text
// (quoted) without carrying control or lookalike characters (T8).
func SafeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= policy.InstallNameMax {
			break
		}
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
