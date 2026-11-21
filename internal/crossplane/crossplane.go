package crossplane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The link rules, strongest first.
const (
	// RuleProjectRoot: the service reported the same project root the
	// coding sessions ran in (the same checkout on the same machine).
	RuleProjectRoot = "project_root"
	// RuleRepository: the service's repository is the coding project's git
	// remote.
	RuleRepository = "repository"
	// RuleUpstream: the service's repository is the upstream of the fork the
	// coding project was cloned from.
	RuleUpstream = "upstream"
)

// ProjectIDLen is the canonical project id length (the first 16 hex of the
// project-root hash; rollup.ProjectIDFromHash on the org).
const ProjectIDLen = 16

// hashHex is sha256 hex, the node's hash of a root path or a remote.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NormalizeRepository reduces a repository URL to the canonical form the
// node stores its git remote in (git.NormalizeRemote), the value stored and
// shown at a raw-content capture level. It fails closed (review finding
// R-C24): git.NormalizeRemote returns an input it cannot parse unchanged,
// so a malformed URL would keep its userinfo ("https://user:token@[bad");
// anything that is not a canonical "host[:port]/path" remote is "" here.
// "" stays "".
func NormalizeRepository(raw string) string {
	n := normalizeRemote(raw)
	if !canonicalRemote(n) {
		return ""
	}
	return n
}

// normalizeRemote is git.NormalizeRemote of the trimmed input: the form a
// node hashes its own git remote in, whatever its shape, so the hashes below
// keep joining a service to every checkout a node reports.
func normalizeRemote(raw string) string {
	return git.NormalizeRemote(strings.TrimSpace(raw))
}

// canonicalRemote reports whether n has git.NormalizeRemote's canonical
// output shape: no scheme, no userinfo, no backslash or space, and not a
// filesystem path.
func canonicalRemote(n string) bool {
	if n == "" || strings.HasPrefix(n, "/") || strings.HasPrefix(n, ".") || strings.ContainsAny(n, "@\\ \t\r\n") || strings.Contains(n, "://") {
		return false
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// RepositoryHash is the hash a service's repository is stored under: sha256
// of the normalized remote, the same value a node ships as git_remote_hash for
// a checkout of that repository. "" for an empty repository. It hashes the
// node's form even where NormalizeRepository fails closed: a hash discloses
// nothing and keeps the join.
func RepositoryHash(raw string) string {
	n := normalizeRemote(raw)
	if n == "" {
		return ""
	}
	return hashHex(n)
}

// RepositoryFormHashes returns the hashes of every match form of a raw
// repository (orgcontract.ProjectRemoteForms over the normalized remote): the
// exact form first, which is RepositoryHash. Empty input has no forms.
func RepositoryFormHashes(raw string) []string {
	forms := orgcontract.ProjectRemoteForms(normalizeRemote(raw))
	out := make([]string, 0, len(forms))
	for _, f := range forms {
		out = append(out, hashHex(f))
	}
	return out
}

// ProjectRootHash is the hash a project root is stored under: sha256 of the
// path as given, the node's root_path_hash. "" for an empty root.
func ProjectRootHash(root string) string {
	if root == "" {
		return ""
	}
	return hashHex(root)
}

// ProjectID is the canonical 16-char project id of a full root hash.
func ProjectID(rootHash string) string {
	if len(rootHash) >= ProjectIDLen {
		return rootHash[:ProjectIDLen]
	}
	return rootHash
}

// ServiceSignals is the identity a service's traces carried in the window.
type ServiceSignals struct {
	// ProjectIDs are canonical project ids of the project roots the traces
	// reported (ProjectID of the trace's project hash).
	ProjectIDs []string
	// RepositoryHashes are the stored repository hashes plus, when the raw
	// repository is known, every RepositoryFormHashes form.
	RepositoryHashes []string
}

// ProjectSignals is one coding project's identity (the resolver's
// project_identity_signals row on the org, the projects row on the machine).
type ProjectSignals struct {
	ProjectID          string // canonical 16-char id
	RemoteHash         string // the project's git remote hash, "" when none
	UpstreamRemoteHash string // its upstream (fork parent) remote hash, "" when none
}

// Match is one coding project a service links to, with the rule that linked
// it.
type Match struct {
	ProjectID string `json:"project_id"`
	Rule      string `json:"rule"`
}

// rule is one row of the link table.
type rule struct {
	name  string
	match func(s signalSets, p ProjectSignals) bool
}

type signalSets struct {
	projects map[string]bool
	repos    map[string]bool
}

// linkRules is the ordered link table: the first row that matches a project
// names the link. A project matching no row is not linked.
var linkRules = []rule{
	{RuleProjectRoot, func(s signalSets, p ProjectSignals) bool { return p.ProjectID != "" && s.projects[p.ProjectID] }},
	{RuleRepository, func(s signalSets, p ProjectSignals) bool { return p.RemoteHash != "" && s.repos[p.RemoteHash] }},
	{RuleUpstream, func(s signalSets, p ProjectSignals) bool {
		return p.UpstreamRemoteHash != "" && s.repos[p.UpstreamRemoteHash]
	}},
}

// RuleNames lists the rule names in table order (the API documents them).
func RuleNames() []string {
	out := make([]string, 0, len(linkRules))
	for _, r := range linkRules {
		out = append(out, r.name)
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x != "" {
			m[x] = true
		}
	}
	return m
}

// Link returns the coding projects a service links to, one Match per
// project id (the strongest rule), sorted by project id. A project id that
// the service named by root but that has no ProjectSignals row still links by
// RuleProjectRoot: the root hash IS the project's identity.
func Link(svc ServiceSignals, projects []ProjectSignals) []Match {
	sets := signalSets{projects: toSet(svc.ProjectIDs), repos: toSet(svc.RepositoryHashes)}
	best := map[string]int{}
	consider := func(p ProjectSignals) {
		for i, r := range linkRules {
			if r.match(sets, p) {
				if cur, ok := best[p.ProjectID]; !ok || i < cur {
					best[p.ProjectID] = i
				}
				return
			}
		}
	}
	for _, p := range projects {
		if p.ProjectID != "" {
			consider(p)
		}
	}
	for id := range sets.projects {
		consider(ProjectSignals{ProjectID: id})
	}
	out := make([]Match, 0, len(best))
	for id, i := range best {
		out = append(out, Match{ProjectID: id, Rule: linkRules[i].name})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ProjectID < out[b].ProjectID })
	return out
}

// StrongestRule returns the strongest (earliest in linkRules) of names; "" when
// names is empty or holds no known rule.
func StrongestRule(names ...string) string {
	best := -1
	for _, n := range names {
		for i, r := range linkRules {
			if r.name == n && (best < 0 || i < best) {
				best = i
			}
		}
	}
	if best < 0 {
		return ""
	}
	return linkRules[best].name
}

// DayCost is one UTC day ("YYYY-MM-DD") of spend.
type DayCost struct {
	Day     string
	CostUSD float64
	Tokens  int64
}

// BuildRunPoint is one day of the build-vs-run series: what coding agents
// spent building the service's projects (build) and what the service spent
// running (run).
type BuildRunPoint struct {
	Date        string  `json:"date"`
	BuildUSD    float64 `json:"build_cost_usd"`
	RunUSD      float64 `json:"run_cost_usd"`
	BuildTokens int64   `json:"build_tokens"`
	RunTokens   int64   `json:"run_tokens"`
}

// BuildRunSeries merges the two daily series onto days (ascending), one point
// per day, zero-filled. A day outside days is dropped (it is outside the
// window); duplicate days in an input are summed.
func BuildRunSeries(days []string, build, run []DayCost) []BuildRunPoint {
	idx := make(map[string]int, len(days))
	out := make([]BuildRunPoint, len(days))
	for i, d := range days {
		idx[d] = i
		out[i].Date = d
	}
	for _, b := range build {
		if i, ok := idx[b.Day]; ok {
			out[i].BuildUSD += b.CostUSD
			out[i].BuildTokens += b.Tokens
		}
	}
	for _, r := range run {
		if i, ok := idx[r.Day]; ok {
			out[i].RunUSD += r.CostUSD
			out[i].RunTokens += r.Tokens
		}
	}
	return out
}

// WindowDays lists the UTC days from since to until inclusive, ascending.
// Empty when until is before since. Capped at maxDays (the newest kept).
func WindowDays(since, until time.Time, maxDays int) []string {
	s := since.UTC().Truncate(24 * time.Hour)
	u := until.UTC().Truncate(24 * time.Hour)
	if u.Before(s) {
		return nil
	}
	var out []string
	for d := s; !d.After(u); d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format("2006-01-02"))
	}
	if maxDays > 0 && len(out) > maxDays {
		out = out[len(out)-maxDays:]
	}
	return out
}

// Regression window bounds.
const (
	// DefaultLookback is how far before a regression's start a coding session
	// still counts as "behind" it: a change built a week before it shipped.
	DefaultLookback = 7 * 24 * time.Hour
	// MaxLookback caps the lookback.
	MaxLookback = 30 * 24 * time.Hour
	// MaxRegressionSpan caps the regression window itself.
	MaxRegressionSpan = 31 * 24 * time.Hour
)

// ErrRegressionWindow is wrapped by every refusal of a regression window.
var ErrRegressionWindow = errors.New("invalid regression window")

// RegressionSpan is the interval whose coding sessions are "behind" a
// regression observed in [From, To): [From-Lookback, To).
type RegressionSpan struct {
	From, To time.Time // the regression window as given
	Since    time.Time // From - Lookback
	Lookback time.Duration
}

// NewRegressionSpan validates a regression window. lookback < 0 means the
// default; it is clamped to MaxLookback. To must follow From and the window
// may not exceed MaxRegressionSpan.
func NewRegressionSpan(from, to time.Time, lookback time.Duration) (RegressionSpan, error) {
	if from.IsZero() || to.IsZero() {
		return RegressionSpan{}, errors.Join(ErrRegressionWindow, errors.New("from and to are required"))
	}
	if !from.Before(to) {
		return RegressionSpan{}, errors.Join(ErrRegressionWindow, errors.New("from must be before to"))
	}
	if to.Sub(from) > MaxRegressionSpan {
		return RegressionSpan{}, errors.Join(ErrRegressionWindow, errors.New("the regression window is longer than 31 days"))
	}
	if lookback < 0 {
		lookback = DefaultLookback
	}
	if lookback > MaxLookback {
		lookback = MaxLookback
	}
	from, to = from.UTC(), to.UTC()
	return RegressionSpan{From: from, To: to, Since: from.Add(-lookback), Lookback: lookback}, nil
}

// When a session sits relative to a regression.
const (
	// WhenBefore: the session was last active in the lookback, before the
	// regression started.
	WhenBefore = "before"
	// WhenDuring: the session was active inside the regression window.
	WhenDuring = "during"
)

// Classify says where a session active over [started, last] sits relative
// to the span: WhenDuring when it overlaps [From, To), WhenBefore when it
// overlaps only [Since, From), "" when it is outside both (a zero last means
// the session is a single instant at started).
func (r RegressionSpan) Classify(started, last time.Time) string {
	if started.IsZero() {
		return ""
	}
	if last.IsZero() || last.Before(started) {
		last = started
	}
	if !started.Before(r.To) || last.Before(r.Since) {
		return ""
	}
	if !last.Before(r.From) {
		return WhenDuring
	}
	return WhenBefore
}
