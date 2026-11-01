package planlimits

import (
	"sort"
	"time"
)

// Provider ids. A provider is a plan or balance a person pays for; it is data
// in Providers, and code never branches on it (CLAUDE.md rule 3). The
// constants exist so the driver table and tests can name rows without typos.
const (
	ProviderClaude     = "claude"
	ProviderChatGPT    = "chatgpt"
	ProviderOpenRouter = "openrouter"
	ProviderDeepSeek   = "deepseek"
	ProviderMoonshot   = "moonshot"
	ProviderKimiCode   = "kimi_code"
	ProviderXAI        = "xai"
	ProviderCopilot    = "github_copilot"
	ProviderCursor     = "cursor"
	ProviderWindsurf   = "windsurf"
	ProviderKiro       = "kiro"
	ProviderAmp        = "amp"
	ProviderAugment    = "augment"
	ProviderOther      = "other"
)

// The provider catalogue (ProviderDef, Providers, groups and gap codes) lives
// in catalog.go.

// Secret keys. A source names the secrets it needs by these keys; the page
// owns the words for each.
const (
	SecretKey     = "key"     // an API key
	SecretMgmt    = "mgmt"    // a management or admin key
	SecretPAT     = "pat"     // a personal access token
	SecretSession = "session" // a pasted browser session (a Cookie header or a bearer token)
	SecretAWS     = "aws_secret"
)

// SecretSpec names one secret a source needs. Secrets live only in the OS
// keychain (internal/keystore), never in the database or config.
type SecretSpec struct {
	Key      string // one of the Secret* keys
	Required bool
}

// ParamSpec names one non-secret parameter a source needs.
type ParamSpec struct {
	Key      string
	Required bool
	Choices  []string // a closed set: the add flow renders a picker
	Numeric  bool
}

// LocalSpec names one read of a vendor app's own local file. The read is
// performed by internal/planlimitslocal, read-only; the bytes stay in memory
// for one refresh.
type LocalSpec struct {
	Key  string // the PlanInput.Local key
	Kind string // LocalFile | LocalSQLiteKV
	Base string // BaseHome | BaseConfig | BaseCodexHome | BaseClaudeHome
	Rel  string // path relative to Base, slash-separated
	Item string // the ItemTable key for LocalSQLiteKV
}

// Local read kinds and path bases.
const (
	LocalFile      = "file"
	LocalSQLiteKV  = "sqlite_kv" // a VS Code style state.vscdb ItemTable value
	BaseHome       = "home"
	BaseConfig     = "config" // os.UserConfigDir: ~/.config, Application Support, %AppData%
	BaseCodexHome  = "codex_home"
	BaseClaudeHome = "claude_home"
)

// SourceDef is one row of the source table: one way to read one provider.
type SourceDef struct {
	ID       string
	Provider string
	Kind     SourceKind
	// Passive sources need no account: they read data Observer already has.
	Passive bool
	Secrets []SecretSpec
	Params  []ParamSpec
	// Hosts are the exact HTTPS hosts this source may reach. The egress
	// package refuses any other host before a credential is attached.
	Hosts []string
	// Command is the vendor command this source runs (argv[0]); the full argv
	// comes from the driver.
	Command string
	// Local lists the vendor-local reads this source needs.
	Local []LocalSpec
	// MinInterval is the floor between two polls.
	MinInterval time.Duration
	// Order is the ladder order within the provider (lower is tried first).
	Order int
	// DocURL is the vendor's own documentation, when there is one.
	DocURL string
	// UserBaseURL marks a self-hosted gateway source: it has no fixed Hosts
	// and reads its host from the account's required base_url parameter,
	// fixed per account and checked by CheckBaseURL at save time and again
	// by the egress package on every request (ledger SUBS-5).
	UserBaseURL bool
}

// Rung is the source's ladder rung.
func (d SourceDef) Rung() Rung { return RungOf(d.Kind) }

// Experimental reports whether the source needs the provider's experimental
// opt-in.
func (d SourceDef) Experimental() bool { return d.Rung() != RungOfficial }

// Source ids.
const (
	SourceClaudeProxy      = "claude.proxy"
	SourceClaudeStatusLine = "claude.statusline"
	SourceCodexLogs        = "chatgpt.logs"
	SourceCodexAppServer   = "chatgpt.appserver"
	SourceOpenRouter       = "openrouter.api"
	SourceDeepSeek         = "deepseek.api"
	SourceMoonshot         = "moonshot.api"
	SourceXAI              = "xai.management"
	SourceCopilotBilling   = "github_copilot.billing"
	SourceKiroCLI          = "kiro.cli"
	SourceAmpCLI           = "amp.cli"
	SourceAugmentCLI       = "augment.cli"
	SourceManual           = "manual"
	SourceClaudeOAuth      = "claude.oauth"
	SourceChatGPTWham      = "chatgpt.web_usage"
	SourceCursorApp        = "cursor.app"
	SourceWindsurfCache    = "windsurf.cache"
	SourceKimiCode         = "kimi_code.api"
)

// Sources is the source table. Order inside a provider is its ladder order.
var Sources = []SourceDef{
	// Rung 1, passive: no account, no network, no credential.
	{ID: SourceClaudeProxy, Provider: ProviderClaude, Kind: KindPassiveProxy, Passive: true, Order: 10},
	{
		ID: SourceClaudeStatusLine, Provider: ProviderClaude, Kind: KindStatusLine, Passive: true, Order: 11,
		DocURL: "https://code.claude.com/docs/en/statusline",
	},
	{ID: SourceCodexLogs, Provider: ProviderChatGPT, Kind: KindPassiveLog, Passive: true, Order: 10},

	// Rung 1, official: off until the user adds an account.
	{
		ID: SourceCodexAppServer, Provider: ProviderChatGPT, Kind: KindVendorRPC, Command: "codex", Order: 20,
		MinInterval: 5 * time.Minute, DocURL: "https://learn.chatgpt.com/docs/app-server",
	},
	{
		ID: SourceOpenRouter, Provider: ProviderOpenRouter, Kind: KindOfficialAPI, Order: 20,
		Secrets: []SecretSpec{{Key: "key", Required: true}, {Key: "mgmt"}},
		Hosts:   []string{"openrouter.ai"}, MinInterval: 2 * time.Minute,
		DocURL: "https://openrouter.ai/docs/api-reference/limits",
	},
	{
		ID: SourceDeepSeek, Provider: ProviderDeepSeek, Kind: KindOfficialAPI, Order: 20,
		Secrets: []SecretSpec{{Key: "key", Required: true}}, Hosts: []string{"api.deepseek.com"},
		MinInterval: 5 * time.Minute, DocURL: "https://api-docs.deepseek.com/api/get-user-balance",
	},
	{
		ID: SourceMoonshot, Provider: ProviderMoonshot, Kind: KindOfficialAPI, Order: 20,
		Secrets: []SecretSpec{{Key: "key", Required: true}},
		Params:  []ParamSpec{{Key: "region", Choices: []string{"global", "china"}}},
		Hosts:   []string{"api.moonshot.ai", "api.moonshot.cn"}, MinInterval: 5 * time.Minute,
		DocURL: "https://platform.kimi.ai/docs/api/balance",
	},
	{
		ID: SourceXAI, Provider: ProviderXAI, Kind: KindAdminAPI, Order: 20,
		Secrets: []SecretSpec{{Key: "mgmt", Required: true}},
		Params:  []ParamSpec{{Key: "team_id", Required: true}},
		Hosts:   []string{"management-api.x.ai"}, MinInterval: 10 * time.Minute,
		DocURL: "https://docs.x.ai/developers/rest-api-reference/management/billing",
	},
	{
		ID: SourceCopilotBilling, Provider: ProviderCopilot, Kind: KindOfficialAPI, Order: 20,
		Secrets: []SecretSpec{{Key: "pat", Required: true}},
		Params:  []ParamSpec{{Key: "username", Required: true}, {Key: "allowance", Numeric: true}},
		Hosts:   []string{"api.github.com"}, MinInterval: 30 * time.Minute,
		DocURL: "https://docs.github.com/en/rest/billing/usage",
	},
	{ID: SourceKiroCLI, Provider: ProviderKiro, Kind: KindVendorCLI, Command: "kiro-cli", Order: 20, MinInterval: 10 * time.Minute},
	{
		ID: SourceAmpCLI, Provider: ProviderAmp, Kind: KindVendorCLI, Command: "amp", Order: 20, MinInterval: 10 * time.Minute,
		DocURL: "https://ampcode.com/manual",
	},
	{ID: SourceAugmentCLI, Provider: ProviderAugment, Kind: KindVendorCLI, Command: "auggie", Order: 20, MinInterval: 10 * time.Minute},

	// Rung 1, manual: typed plan facts, always estimated. Valid for any
	// provider (the account names it).
	{
		ID: SourceManual, Provider: "", Kind: KindManual, Order: 90,
		Params: []ParamSpec{
			{Key: "plan"},
			{Key: "unit", Required: true, Choices: []string{"usd", "requests", "credits", "percent"}},
			{Key: "allowance", Required: true, Numeric: true},
			{Key: "used", Numeric: true},
			{Key: "renews_day", Numeric: true},
			{Key: "window", Choices: []string{"monthly", "weekly", "daily"}},
		},
	},

	// Rung 2, experimental: per-provider opt-in, never on by default, only
	// polled when rung 1 gives no fresh coverage (ShouldPoll).
	{
		ID: SourceClaudeOAuth, Provider: ProviderClaude, Kind: KindBorrowedToken, Order: 50,
		Hosts: []string{"api.anthropic.com"}, MinInterval: 5 * time.Minute,
		Local: []LocalSpec{{Key: "creds", Kind: LocalFile, Base: BaseClaudeHome, Rel: ".credentials.json"}},
	},
	{
		ID: SourceChatGPTWham, Provider: ProviderChatGPT, Kind: KindBorrowedToken, Order: 50,
		Hosts: []string{"chatgpt.com"}, MinInterval: 5 * time.Minute,
		Local: []LocalSpec{{Key: "auth", Kind: LocalFile, Base: BaseCodexHome, Rel: "auth.json"}},
	},
	{
		ID: SourceCursorApp, Provider: ProviderCursor, Kind: KindBorrowedToken, Order: 50,
		Hosts: []string{"cursor.com"}, MinInterval: 10 * time.Minute,
		Local: []LocalSpec{{
			Key: "token", Kind: LocalSQLiteKV, Base: BaseConfig,
			Rel: "Cursor/User/globalStorage/state.vscdb", Item: "cursorAuth/accessToken",
		}},
	},
	{
		ID: SourceWindsurfCache, Provider: ProviderWindsurf, Kind: KindLocalState, Order: 50,
		MinInterval: 5 * time.Minute,
		Local: []LocalSpec{{
			Key: "plan", Kind: LocalSQLiteKV, Base: BaseConfig,
			Rel: "Windsurf/User/globalStorage/state.vscdb", Item: "windsurf.settings.cachedPlanInfo",
		}},
	},
	{
		ID: SourceKimiCode, Provider: ProviderKimiCode, Kind: KindUndocumented, Order: 50,
		Secrets: []SecretSpec{{Key: "key", Required: true}}, Hosts: []string{"api.kimi.com"}, MinInterval: 10 * time.Minute,
	},
}

// addSources appends source rows. Each src_*.go file calls it from init, so
// parallel lanes add sources without editing one shared slice literal.
func addSources(rows ...SourceDef) { Sources = append(Sources, rows...) }

// SourceByID returns the source row.
func SourceByID(id string) (SourceDef, bool) {
	for _, s := range Sources {
		if s.ID == id {
			return s, true
		}
	}
	return SourceDef{}, false
}

// SourcesFor returns the provider's sources in ladder order. The manual
// source applies to every provider and is listed last.
func SourcesFor(provider string) []SourceDef {
	var out []SourceDef
	for _, s := range Sources {
		if s.Provider == provider || s.Kind == KindManual {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// AccountSourceAllowed reports whether an account may use source src for
// provider: the source exists, is not passive, and serves the provider
// (manual serves every provider).
func AccountSourceAllowed(provider, src string) bool {
	d, ok := SourceByID(src)
	if !ok || d.Passive {
		return false
	}
	if _, ok := ProviderByID(provider); !ok {
		return false
	}
	return d.Kind == KindManual || d.Provider == provider
}

// defaultMinInterval applies when a source row leaves MinInterval unset.
const defaultMinInterval = 5 * time.Minute

// MinIntervalOf returns the source's poll floor.
func MinIntervalOf(src string) time.Duration {
	if d, ok := SourceByID(src); ok && d.MinInterval > 0 {
		return d.MinInterval
	}
	return defaultMinInterval
}
