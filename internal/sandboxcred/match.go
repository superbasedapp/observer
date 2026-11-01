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
)

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
	Live         bool
	Provider     string
	SentinelHash string
	TokenHash    string
	// KeyStored: the user's key for the provider is in the keystore.
	KeyStored bool
}

// Decision is a match outcome: inject (into Header with the key rendered
// by Auth) or leave the request untouched.
type Decision struct {
	Inject bool
	Code   Code
	Auth   AuthForm
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
// with code.
type matchRule struct {
	name  string
	fails func(Request, RunFacts, Provider) bool
	code  Code
}

// matchRules are walked top-down (decision 3 of lane GATES-SBX); every row
// must pass for the key to be added. A request that fails one goes upstream
// untouched and the provider answers its own 401 to the sentinel.
var matchRules = []matchRule{
	{"no run", func(r Request, _ RunFacts, _ Provider) bool { return r.RunID == "" }, CodeNoRun},
	{"no record", func(_ Request, f RunFacts, _ Provider) bool { return !f.Found }, CodeRunNotLive},
	{"not relayed", func(r Request, f RunFacts, _ Provider) bool { return !equalHash(r.Token, f.TokenHash) }, CodeNotRelayed},
	{"not live", func(_ Request, f RunFacts, _ Provider) bool { return !f.Live }, CodeRunNotLive},
	{"provider", func(_ Request, f RunFacts, p Provider) bool { return p.ID == "" || p.ID != f.Provider }, CodeUnknownProv},
	{"wrong auth form", func(r Request, _ RunFacts, p Provider) bool {
		return presented(p, r) == "" && presentedAnywhere(r) != ""
	}, CodeWrongAuthForm},
	{"not the run's sentinel", func(r Request, f RunFacts, p Provider) bool {
		return !equalHash(presented(p, r), f.SentinelHash)
	}, CodeNotSentinel},
	{"wrong host", func(r Request, _ RunFacts, p Provider) bool {
		return !strings.EqualFold(strings.TrimSuffix(r.Host, "."), p.Host)
	}, CodeWrongHost},
	{"no key", func(_ Request, f RunFacts, _ Provider) bool { return !f.KeyStored }, CodeNoKey},
}

// Decide walks the table for one request.
func Decide(r Request, f RunFacts) Decision {
	p, _ := ProviderFor(f.Provider)
	for _, rule := range matchRules {
		if rule.fails(r, f, p) {
			return Decision{Code: rule.code}
		}
	}
	return Decision{Inject: true, Code: CodeInjected, Auth: p.Auth}
}
