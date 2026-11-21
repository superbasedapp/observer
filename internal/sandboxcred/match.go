package sandboxcred

import "strings"

// Code names a match outcome.
type Code string

// The closed Code vocabulary.
const (
	CodeInjected      Code = "injected"
	CodeNoRun         Code = "no_run"
	CodeNotRelayed    Code = "not_relayed"
	CodeRunNotLive    Code = "run_not_live"
	CodeUnknownProv   Code = "unknown_provider"
	CodeNotSentinel   Code = "not_sentinel"
	CodeWrongHost     Code = "wrong_host"
	CodeWrongAuthForm Code = "wrong_auth_form"
	CodeNoKey         Code = "no_key"
	// The local-run codes (lane N3, SBX-NET-2).
	CodeUnknownLane  Code = "unknown_lane"
	CodeWrongCustody Code = "wrong_custody"
	CodeHelperGone   Code = "helper_gone"
)

// Lane is how a run's model requests reach the proxy, as its injection
// record says (the host side wrote it; the request cannot choose it).
type Lane string

// The closed Lane vocabulary.
const (
	// LaneHosted (the zero value, so a record written before lanes reads
	// as hosted): the home side of a hosted run's relay stamps the run.
	LaneHosted Lane = ""
	// LaneLocal: the host helper of a local run (bwrap or oci-runc on the
	// proxy_only tier, or on the internet tier with the provider-host
	// block) stamps the run on its model-proxy forward.
	LaneLocal Lane = "local"
)

// Valid reports whether l is in the closed vocabulary.
func (l Lane) Valid() bool { return l == LaneHosted || l == LaneLocal }

// CustodyLocal is the key custody a local run's selection records
// (sandboxvocab.CustodyHostBound; a test in cmd/observer pins the two
// spellings equal, this package is stdlib only): the key stays on the
// host, and with injection the box holds only the sentinel.
const CustodyLocal = "host_bound"

// Request is what the proxy read from one model request.
type Request struct {
	// RunID is the run header the home side of a run's relay sets.
	RunID string
	// Token is the relay token header.
	Token string
	// Host is the upstream host the request goes to.
	Host string
	// XAPIKey, Authorization and GoogKey are the request's credential
	// headers as they would go upstream.
	XAPIKey, Authorization, GoogKey string
}

// RunFacts are the run's injection record, read by the caller.
type RunFacts struct {
	// Found: an injection record exists for the run.
	Found bool
	// Live: the run is live (its relay record exists and the injection
	// record is not past its end).
	Live bool
	// Provider and SentinelHash are a one-provider record's binding (the
	// record shape every run had before a run could bind several); Bindings
	// are a record's bindings when it has several (gap H2). With Bindings
	// set, Provider and SentinelHash are not read.
	Provider     string
	SentinelHash string
	Bindings     []Binding
	TokenHash    string
	// KeyStored: the user's key for the provider SelectBinding picks for
	// this request is in the keystore.
	KeyStored bool
	// Lane is the record's lane, Custody its key custody, and HelperLive
	// whether the run's host helper still holds the run's liveness lock
	// (read for a local record; a hosted record is judged by Live alone).
	Lane       Lane
	Custody    string
	HelperLive bool
}

// Binding is one provider a run binds: the provider and the hash of the
// run's own sentinel for it.
type Binding struct {
	Provider     string
	SentinelHash string
}

// bindings are the run's bindings: Bindings, or the one-provider record's
// pair (always one entry then, an empty one for an empty record, so such a
// record is refused by the provider row as before).
func (f RunFacts) bindings() []Binding {
	if len(f.Bindings) > 0 {
		return f.Bindings
	}
	return []Binding{{Provider: f.Provider, SentinelHash: f.SentinelHash}}
}

// SelectBinding picks the binding a request is judged against. A run with
// one binding is judged against it, exactly as before runs could bind
// several. With several, the request's destination decides: the binding
// whose provider's model host the request goes to; else the binding whose
// own sentinel the request presents in that provider's auth form (so the
// host row names a sentinel sent to a host that is not its provider's);
// else the first. Every match row then holds against that one binding, so
// a provider's key is only ever added on that provider's own host and only
// for that provider's own sentinel.
func SelectBinding(r Request, f RunFacts) Binding {
	bs := f.bindings()
	if len(bs) == 1 {
		return bs[0]
	}
	for _, b := range bs {
		if p, ok := ProviderFor(b.Provider); ok && hostIs(r.Host, p.Host) {
			return b
		}
	}
	for _, b := range bs {
		if p, ok := ProviderFor(b.Provider); ok && equalHash(presented(p, r), b.SentinelHash) {
			return b
		}
	}
	return bs[0]
}

// Decision is a match outcome: inject (into Header with the key rendered
// by Auth, the key of Provider) or leave the request untouched.
type Decision struct {
	Inject   bool
	Code     Code
	Auth     AuthForm
	Provider string
}

// presented is the credential the request carries in the provider's form.
func presented(p Provider, r Request) string {
	switch p.Auth {
	case AuthBearer:
		v, ok := strings.CutPrefix(r.Authorization, "Bearer ")
		if !ok {
			return ""
		}
		return v
	case AuthGoogKey:
		return r.GoogKey
	}
	return r.XAPIKey
}

// presentedAnywhere is a sentinel carried in any credential header.
func presentedAnywhere(r Request) string {
	for _, v := range []string{r.XAPIKey, strings.TrimPrefix(r.Authorization, "Bearer "), r.GoogKey} {
		if IsSentinel(v) {
			return v
		}
	}
	return ""
}

// matchRule is one row: when fails holds, the request is left untouched
// with code. b is the binding SelectBinding picked and p its provider row.
type matchRule struct {
	name  string
	fails func(r Request, f RunFacts, b Binding, p Provider) bool
	code  Code
}

// matchRules are walked top-down (decision 3 of lane GATES-SBX); every row
// must pass for the key to be added. A request that fails one goes upstream
// untouched and the provider answers its own 401 to the sentinel.
var matchRules = []matchRule{
	{"no run", func(r Request, _ RunFacts, _ Binding, _ Provider) bool { return r.RunID == "" }, CodeNoRun},
	{"no record", func(_ Request, f RunFacts, _ Binding, _ Provider) bool { return !f.Found }, CodeRunNotLive},
	{"not relayed", func(r Request, f RunFacts, _ Binding, _ Provider) bool { return !equalHash(r.Token, f.TokenHash) }, CodeNotRelayed},
	{"not live", func(_ Request, f RunFacts, _ Binding, _ Provider) bool { return !f.Live }, CodeRunNotLive},
	{"unknown lane", func(_ Request, f RunFacts, _ Binding, _ Provider) bool { return !f.Lane.Valid() }, CodeUnknownLane},
	{"local custody", func(_ Request, f RunFacts, _ Binding, _ Provider) bool {
		return f.Lane == LaneLocal && f.Custody != CustodyLocal
	}, CodeWrongCustody},
	{"local helper gone", func(_ Request, f RunFacts, _ Binding, _ Provider) bool {
		return f.Lane == LaneLocal && !f.HelperLive
	}, CodeHelperGone},
	{"provider", func(_ Request, _ RunFacts, b Binding, p Provider) bool { return p.ID == "" || p.ID != b.Provider }, CodeUnknownProv},
	{"wrong auth form", func(r Request, _ RunFacts, _ Binding, p Provider) bool {
		return presented(p, r) == "" && presentedAnywhere(r) != ""
	}, CodeWrongAuthForm},
	{"not the run's sentinel", func(r Request, _ RunFacts, b Binding, p Provider) bool {
		return !equalHash(presented(p, r), b.SentinelHash)
	}, CodeNotSentinel},
	{"wrong host", func(r Request, _ RunFacts, _ Binding, p Provider) bool {
		return !hostIs(r.Host, p.Host)
	}, CodeWrongHost},
	{"no key", func(_ Request, f RunFacts, _ Binding, _ Provider) bool { return !f.KeyStored }, CodeNoKey},
}

// Decide walks the table for one request, against the binding
// SelectBinding picks.
func Decide(r Request, f RunFacts) Decision {
	b := SelectBinding(r, f)
	p, _ := ProviderFor(b.Provider)
	for _, rule := range matchRules {
		if rule.fails(r, f, b, p) {
			return Decision{Code: rule.code}
		}
	}
	return Decision{Inject: true, Code: CodeInjected, Auth: p.Auth, Provider: p.ID}
}
