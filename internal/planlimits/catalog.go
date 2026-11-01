package planlimits

// catalog.go is the provider catalogue: one row per plan or balance a person
// can track. The coverage target is the provider list of the reference
// project CodexBar (github.com/steipete/CodexBar, MIT; D-681): every CodexBar
// provider id is named in some row's Ref, and TestEveryReferenceProviderHasARow
// pins that. Only facts (which vendors exist, which windows they expose) were
// taken from the reference; no code.
//
// A row says what the vendor exposes (Shows) and, when Observer cannot read
// it live, why not (Gap). How Observer reads a provider is the source table
// (registry.go plus the src_*.go files); coverage and auth method are derived
// from the sources, never typed twice (CoverageOf, AuthMethodsOf).
//
// Rows are grouped in blocks by the build lane that owns them, so parallel
// edits never touch the same lines. The picker sorts by label; this order
// only decides card order on the page.

// Provider groups (the "kind" of a provider in the picker).
const (
	GroupPlans   = "plans"   // a coding plan or subscription with usage windows
	GroupBalance = "balance" // a prepaid or pay-as-you-go balance
	GroupUsage   = "usage"   // usage-based billing: spend and budgets, no prepaid balance
)

// Gap codes: why a provider has no live reading. Codes, never prose; the
// dashboard owns the words. "" means a live source exists.
const (
	GapNone           = ""
	GapNoQuotaAPI     = "no_quota_api"     // the vendor exposes no plan, balance or spend reading
	GapPaidProbe      = "paid_probe"       // readable only by sending a paid request
	GapVendorEnded    = "vendor_ended"     // the vendor ended the sign-in route the reading needs
	GapNotAPlan       = "not_a_plan"       // a local tool with no plan or balance to track
	GapNeedsProcess   = "needs_process"    // needs reading another app's running process
	GapNeedsPassword  = "needs_password"   // needs the account password, which Observer never takes
	GapTrafficOnly    = "traffic_only"     // only Observer's own capture of your usage
	GapMacOnly        = "mac_only"         // the vendor keeps the reading only in macOS app data
	GapNeedsBrowser   = "needs_browser"    // needs a live browser (a challenge page or a WebView)
	GapCloudCredsOnly = "cloud_creds_only" // needs cloud account credentials Observer does not handle yet
	GapTokenExchange  = "token_exchange"   // needs a short-lived token minted from your sign-in, which Observer never does
	GapPageScrape     = "page_scrape"      // the reading is hidden in a web page whose code changes on every release
)

// AllGaps lists every gap code, for vocabulary tests.
func AllGaps() []string {
	return []string{
		GapNoQuotaAPI, GapPaidProbe, GapVendorEnded, GapNotAPlan, GapNeedsProcess, GapNeedsPassword,
		GapTrafficOnly, GapMacOnly, GapNeedsBrowser, GapCloudCredsOnly, GapTokenExchange, GapPageScrape,
	}
}

// Shows codes: what a provider's vendor reports. Window keys where one exists.
const (
	Shows5h        = "5h"
	ShowsDaily     = "daily"
	ShowsWeekly    = "weekly"
	ShowsMonthly   = "monthly"
	ShowsCycle     = "cycle"
	ShowsBalance   = "balance"
	ShowsCredits   = "credits"
	ShowsSpend     = "spend"
	ShowsBudget    = "budget"
	ShowsKeyCap    = "key_cap"
	ShowsRateLimit = "rate_limit"
	ShowsModel     = "model"
)

// AllShows lists every shows code, for vocabulary tests.
func AllShows() []string {
	return []string{
		Shows5h, ShowsDaily, ShowsWeekly, ShowsMonthly, ShowsCycle, ShowsBalance, ShowsCredits,
		ShowsSpend, ShowsBudget, ShowsKeyCap, ShowsRateLimit, ShowsModel,
	}
}

// ProviderDef is one row of the provider catalogue.
type ProviderDef struct {
	ID    string
	Group string
	// Ref names the CodexBar provider ids this row covers. A row with no Ref
	// is Observer's own (manual "other", or a split such as anthropic_api).
	Ref []string
	// Shows lists what the vendor reports (Shows* codes).
	Shows []string
	// Gap says why there is no live source; GapNone when one exists.
	Gap string
	// Tools are integration-registry tool ids that draw from this plan. They
	// scope the "estimated from your usage" spend of a manual entry and are
	// test-checked against the registry.
	Tools []string
}

// sh is a short constructor for a Shows list.
func sh(v ...string) []string { return v }

// Providers is the provider catalogue.
var Providers = []ProviderDef{
	// --- Shipped in the first build (lane P1) ----------------------------------
	{ID: ProviderClaude, Group: GroupPlans, Ref: []string{"claude"}, Shows: sh(Shows5h, ShowsWeekly, ShowsModel, ShowsSpend), Tools: []string{"claude-code"}},
	{ID: ProviderChatGPT, Group: GroupPlans, Ref: []string{"codex"}, Shows: sh(Shows5h, ShowsWeekly, ShowsCredits), Tools: []string{"codex"}},
	{ID: ProviderCopilot, Group: GroupPlans, Ref: []string{"copilot"}, Shows: sh(ShowsMonthly, ShowsSpend), Tools: []string{"copilot", "copilot-cli"}},
	{ID: ProviderCursor, Group: GroupPlans, Ref: []string{"cursor"}, Shows: sh(ShowsCycle, ShowsSpend), Tools: []string{"cursor"}},
	{ID: ProviderWindsurf, Group: GroupPlans, Ref: []string{"windsurf"}, Shows: sh(ShowsDaily, ShowsWeekly), Tools: []string{"devin"}},
	{ID: ProviderKiro, Group: GroupPlans, Ref: []string{"kiro"}, Shows: sh(ShowsMonthly, ShowsCredits), Tools: []string{"kiro-cli"}},
	{ID: ProviderKimiCode, Group: GroupPlans, Ref: []string{"kimi"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly), Tools: []string{"kimi-code"}},
	{ID: ProviderAmp, Group: GroupPlans, Ref: []string{"amp"}, Shows: sh(ShowsDaily, ShowsCredits)},
	{ID: ProviderAugment, Group: GroupPlans, Ref: []string{"augment"}, Shows: sh(ShowsMonthly, ShowsCredits)},
	{ID: ProviderOpenRouter, Group: GroupBalance, Ref: []string{"openrouter"}, Shows: sh(ShowsBalance, ShowsKeyCap, ShowsSpend)},
	{ID: ProviderDeepSeek, Group: GroupBalance, Ref: []string{"deepseek"}, Shows: sh(ShowsBalance)},
	{ID: ProviderMoonshot, Group: GroupBalance, Ref: []string{"moonshot"}, Shows: sh(ShowsBalance)},
	{ID: ProviderXAI, Group: GroupBalance, Ref: []string{"xai"}, Shows: sh(ShowsBalance, ShowsSpend, ShowsBudget)},
	{ID: ProviderOther, Group: GroupPlans},

	// --- Lane A: API-key vendors, part 1 --------------------------------------
	{ID: "clinepass", Group: GroupPlans, Ref: []string{"clinepass"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly), Tools: []string{"cline", "cline-cli"}},
	{ID: "opencode_go", Group: GroupPlans, Ref: []string{"opencodego"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly), Tools: []string{"opencode"}},
	{ID: "factory", Group: GroupPlans, Ref: []string{"factory"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly, ShowsCycle, ShowsBalance), Tools: []string{"droid"}},
	{ID: "fireworks", Group: GroupUsage, Ref: []string{"fireworks"}, Shows: sh(ShowsSpend)},
	{ID: "zai", Group: GroupPlans, Ref: []string{"zai"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly)},
	{ID: "minimax", Group: GroupPlans, Ref: []string{"minimax"}, Shows: sh(Shows5h, ShowsWeekly, ShowsModel, ShowsBalance)},
	{ID: "kilo", Group: GroupBalance, Ref: []string{"kilo"}, Shows: sh(ShowsBalance, ShowsCycle), Tools: []string{"kilo-code", "kilo-code-cli"}},
	{ID: "synthetic", Group: GroupPlans, Ref: []string{"synthetic"}, Shows: sh(Shows5h, ShowsWeekly, ShowsRateLimit)},
	{ID: "elevenlabs", Group: GroupPlans, Ref: []string{"elevenlabs"}, Shows: sh(ShowsMonthly)},
	{ID: "warp", Group: GroupPlans, Ref: []string{"warp"}, Shows: sh(ShowsCycle, ShowsCredits)},
	{ID: "deepinfra", Group: GroupBalance, Ref: []string{"deepinfra"}, Shows: sh(ShowsBalance, ShowsSpend, ShowsBudget)},
	{ID: "codebuff", Group: GroupPlans, Ref: []string{"codebuff"}, Shows: sh(ShowsCycle, ShowsCredits, ShowsWeekly), Tools: []string{"freebuff"}},
	{ID: "venice", Group: GroupBalance, Ref: []string{"venice"}, Shows: sh(ShowsBalance, ShowsCredits)},
	{ID: "command_code", Group: GroupPlans, Ref: []string{"commandcode"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly, ShowsBalance), Tools: []string{"command-code"}},
	{ID: "poe", Group: GroupBalance, Ref: []string{"poe"}, Shows: sh(ShowsBalance)},
	{ID: "chutes", Group: GroupPlans, Ref: []string{"chutes"}, Shows: sh(ShowsMonthly, ShowsRateLimit)},
	{ID: "neuralwatt", Group: GroupPlans, Ref: []string{"neuralwatt"}, Shows: sh(ShowsCycle, ShowsBalance, ShowsKeyCap, ShowsSpend)},
	{ID: "zenmux", Group: GroupPlans, Ref: []string{"zenmux"}, Shows: sh(Shows5h, ShowsWeekly, ShowsBalance)},
	{ID: "aiand", Group: GroupUsage, Ref: []string{"aiand"}, Shows: sh(ShowsSpend)},
	{ID: "ibm_bob", Group: GroupPlans, Ref: []string{"ibmbob"}, Shows: sh(ShowsMonthly, ShowsBudget)},
	{ID: "hugging_face", Group: GroupUsage, Ref: []string{"huggingface"}, Shows: sh(ShowsSpend, ShowsMonthly, ShowsBudget)},
	{ID: "v0", Group: GroupPlans, Ref: []string{"v0"}, Shows: sh(ShowsCycle, ShowsCredits, ShowsRateLimit)},

	// --- Lane B: API-key vendors, part 2, and self-hosted gateways --------------
	{ID: "llm_proxy", Group: GroupUsage, Ref: []string{"llmproxy"}, Shows: sh(ShowsRateLimit, ShowsSpend)},
	{ID: "litellm", Group: GroupUsage, Ref: []string{"litellm"}, Shows: sh(ShowsBudget, ShowsSpend)},
	{ID: "bifrost", Group: GroupUsage, Ref: []string{"bifrost"}, Shows: sh(ShowsBudget, ShowsRateLimit)},
	{ID: "aixy", Group: GroupUsage, Ref: []string{"aixy"}, Shows: sh(ShowsBudget, ShowsSpend)},
	{ID: "deepgram", Group: GroupBalance, Ref: []string{"deepgram"}, Shows: sh(ShowsBalance)},
	{ID: "clawrouter", Group: GroupUsage, Ref: []string{"clawrouter"}, Shows: sh(ShowsMonthly, ShowsBudget, ShowsSpend)},
	{ID: "sub2api", Group: GroupUsage, Ref: []string{"sub2api"}, Shows: sh(Shows5h, ShowsDaily, ShowsWeekly, ShowsMonthly, ShowsKeyCap, ShowsBalance)},
	{ID: "wayfinder", Group: GroupUsage, Ref: []string{"wayfinder"}, Gap: GapNotAPlan},
	{ID: "llmman", Group: GroupUsage, Ref: []string{"llmman"}, Gap: GapNotAPlan},
	{ID: "charm_hyper", Group: GroupBalance, Ref: []string{"hyper"}, Shows: sh(ShowsCredits)},
	{ID: "gitkraken_ai", Group: GroupPlans, Ref: []string{"gitkraken"}, Shows: sh(ShowsWeekly, ShowsCredits)},
	{ID: "devpass", Group: GroupPlans, Ref: []string{"devpass"}, Shows: sh(ShowsCycle, ShowsWeekly, ShowsKeyCap, ShowsSpend)},
	{ID: "atlas_cloud", Group: GroupBalance, Ref: []string{"atlascloud"}, Shows: sh(ShowsBalance)},
	{ID: "vercel_ai_gateway", Group: GroupBalance, Ref: []string{"vercel"}, Shows: sh(ShowsBalance, ShowsSpend)},
	{ID: "xkiro", Group: GroupPlans, Ref: []string{"xkiro"}, Shows: sh(ShowsDaily, ShowsBalance)},
	{ID: "tavily", Group: GroupPlans, Ref: []string{"tavily"}, Shows: sh(ShowsMonthly, ShowsCredits, ShowsKeyCap)},
	{ID: "linkup", Group: GroupBalance, Ref: []string{"linkup"}, Shows: sh(ShowsBalance)},
	{ID: "exa", Group: GroupUsage, Ref: []string{"exa"}, Shows: sh(ShowsSpend)},
	{ID: "cosmic_ai", Group: GroupPlans, Ref: []string{"cosmic"}, Shows: sh(ShowsCycle)},
	{ID: "aerostack", Group: GroupPlans, Ref: []string{"aerostack"}, Shows: sh(ShowsMonthly, ShowsBalance)},
	{ID: "sail_research", Group: GroupBalance, Ref: []string{"sailresearch"}, Shows: sh(ShowsBalance, ShowsSpend)},
	{ID: "sofya", Group: GroupBalance, Ref: []string{"sofya"}, Shows: sh(ShowsCredits)},
	{ID: "fal", Group: GroupBalance, Ref: []string{"fal"}, Shows: sh(ShowsBalance)},
	{ID: "flora", Group: GroupBalance, Ref: []string{"flora"}, Shows: sh(ShowsBalance, ShowsSpend)},

	// --- Lane C1: pasted browser-session vendors, part 1 -----------------------
	{ID: "opencode", Group: GroupPlans, Ref: []string{"opencode"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly, ShowsBalance, ShowsSpend), Tools: []string{"opencode"}},
	{ID: "alibaba_coding_plan", Group: GroupPlans, Ref: []string{"alibaba"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly)},
	{ID: "alibaba_token_plan", Group: GroupPlans, Ref: []string{"alibabatokenplan"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly)},
	{ID: "qwen_cloud", Group: GroupPlans, Ref: []string{"qwencloud"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly)},
	{ID: "devin", Group: GroupPlans, Ref: []string{"devin"}, Shows: sh(ShowsDaily, ShowsWeekly, ShowsBalance)},
	{ID: "manus", Group: GroupPlans, Ref: []string{"manus"}, Shows: sh(ShowsMonthly, ShowsDaily, ShowsCredits)},
	{ID: "t3_chat", Group: GroupPlans, Ref: []string{"t3chat"}, Shows: sh(ShowsRateLimit, ShowsMonthly)},
	{ID: "langdock", Group: GroupPlans, Ref: []string{"langdock"}, Shows: sh(Shows5h, ShowsWeekly)},
	{ID: "ollama", Group: GroupPlans, Ref: []string{"ollama"}, Shows: sh(ShowsMonthly, ShowsBalance)},
	{ID: "zed", Group: GroupPlans, Ref: []string{"zed"}, Shows: sh(ShowsCycle, ShowsSpend, ShowsBudget), Tools: []string{"zed"}},
	{ID: "perplexity", Group: GroupPlans, Ref: []string{"perplexity"}, Shows: sh(ShowsMonthly, ShowsCredits, ShowsBalance), Tools: []string{"perplexity-web"}},
	{ID: "xiaomi_mimo", Group: GroupBalance, Ref: []string{"mimo"}, Shows: sh(ShowsBalance, ShowsMonthly)},
	{ID: "sakana", Group: GroupPlans, Ref: []string{"sakana"}, Shows: sh(Shows5h, ShowsWeekly, ShowsBalance, ShowsSpend)},
	{ID: "abacus", Group: GroupPlans, Ref: []string{"abacus"}, Shows: sh(ShowsMonthly, ShowsCredits)},
	{ID: "mistral", Group: GroupPlans, Ref: []string{"mistral"}, Shows: sh(ShowsMonthly, ShowsBalance, ShowsSpend), Tools: []string{"mistral-code"}},
	{ID: "qoder", Group: GroupPlans, Ref: []string{"qoder"}, Shows: sh(ShowsCycle, ShowsCredits), Tools: []string{"qoder"}},

	// --- Lane C2: pasted browser-session vendors, part 2 -----------------------
	{ID: "stepfun", Group: GroupPlans, Ref: []string{"stepfun"}, Shows: sh(Shows5h, ShowsWeekly, ShowsCredits)},
	// Groq: the console's short-lived session token is minted from the
	// long-lived one through Stytch; Observer never mints a token.
	{ID: "groq", Group: GroupUsage, Ref: []string{"groq"}, Shows: sh(ShowsSpend), Gap: GapTokenExchange},
	{ID: "helmcode", Group: GroupPlans, Ref: []string{"helmcode"}, Shows: sh(ShowsModel, ShowsMonthly, ShowsBalance)},
	{ID: "longcat", Group: GroupPlans, Ref: []string{"longcat"}, Shows: sh(ShowsCredits)},
	// ZoomMate: the credits call needs a bearer minted from the session by
	// a first request, so the second depends on the first one's body.
	{ID: "zoommate", Group: GroupPlans, Ref: []string{"zoommate"}, Shows: sh(ShowsCredits, ShowsCycle), Gap: GapTokenExchange},
	{ID: "x_api", Group: GroupBalance, Ref: []string{"xapi"}, Shows: sh(ShowsBalance, ShowsMonthly)},
	{ID: "notion_ai", Group: GroupPlans, Ref: []string{"notion"}, Shows: sh(Shows5h, ShowsMonthly)},
	{ID: "replicate", Group: GroupUsage, Ref: []string{"replicate"}, Shows: sh(ShowsSpend, ShowsBalance)},
	{ID: "raycast", Group: GroupPlans, Ref: []string{"raycast"}, Shows: sh(ShowsMonthly, ShowsCredits)},
	// TypeSafe and muse.ai: the reading is a Next.js server action whose id
	// changes on every deploy and is found only by scraping the page's
	// script chunks first.
	{ID: "typesafe", Group: GroupBalance, Ref: []string{"typesafe"}, Shows: sh(ShowsBalance, ShowsSpend), Gap: GapPageScrape},
	{ID: "muse_ai", Group: GroupPlans, Ref: []string{"museai"}, Shows: sh(ShowsWeekly), Gap: GapPageScrape},
	{ID: "lithosai", Group: GroupBalance, Ref: []string{"lithosai"}, Shows: sh(ShowsBalance, ShowsSpend)},
	{ID: "workbuddy", Group: GroupPlans, Ref: []string{"workbuddy"}, Shows: sh(ShowsCycle, ShowsCredits)},
	{ID: "tinyapi", Group: GroupBalance, Ref: []string{"tinyapi"}, Shows: sh(ShowsCredits)},
	{ID: "parallel", Group: GroupBalance, Ref: []string{"parallel"}, Shows: sh(ShowsBalance)},
	{ID: "claude_platform", Group: GroupBalance, Ref: []string{"claudeplatform"}, Shows: sh(ShowsBalance, ShowsSpend)},

	// --- Lane D: vendor-local, CLI, admin and cloud vendors ---------------------
	{ID: "openai_api", Group: GroupUsage, Ref: []string{"openai"}, Shows: sh(ShowsSpend, ShowsBalance)},
	{ID: "anthropic_api", Group: GroupUsage, Ref: []string{"claude"}, Shows: sh(ShowsSpend)},
	{ID: "azure_openai", Group: GroupUsage, Ref: []string{"azureopenai"}, Gap: GapNoQuotaAPI},
	{ID: "gemini", Group: GroupPlans, Ref: []string{"gemini"}, Shows: sh(ShowsDaily, ShowsModel), Gap: GapVendorEnded, Tools: []string{"gemini-cli"}},
	{ID: "antigravity", Group: GroupPlans, Ref: []string{"antigravity"}, Shows: sh(ShowsModel), Gap: GapNeedsProcess, Tools: []string{"antigravity"}},
	{ID: "vertex_ai", Group: GroupUsage, Ref: []string{"vertexai"}, Shows: sh(ShowsRateLimit), Gap: GapCloudCredsOnly},
	{ID: "jetbrains_ai", Group: GroupPlans, Ref: []string{"jetbrains"}, Shows: sh(ShowsMonthly, ShowsCredits), Tools: []string{"junie"}},
	{ID: "doubao", Group: GroupPlans, Ref: []string{"doubao"}, Shows: sh(Shows5h, ShowsWeekly, ShowsMonthly)},
	{ID: "aws_bedrock", Group: GroupUsage, Ref: []string{"bedrock"}, Shows: sh(ShowsSpend, ShowsBudget)},
	{ID: "grok", Group: GroupPlans, Ref: []string{"grok"}, Shows: sh(ShowsWeekly, ShowsMonthly, ShowsSpend), Tools: []string{"grok"}},
	{ID: "nous_portal", Group: GroupBalance, Ref: []string{"nous"}, Shows: sh(ShowsMonthly, ShowsBalance), Tools: []string{"hermes"}},
	{ID: "muse_code", Group: GroupPlans, Ref: []string{"muse"}, Shows: sh(Shows5h, ShowsWeekly), Tools: []string{"muse"}},
	{ID: "coderabbit", Group: GroupUsage, Ref: []string{"coderabbit"}, Shows: sh(ShowsCycle)},
	{ID: "pi", Group: GroupUsage, Ref: []string{"pi"}, Gap: GapTrafficOnly, Tools: []string{"pi"}},

	// --- 2026-10-21 capture wave (AP-134; src_wave1021.go) ---------------------
	// Not in the reference list (no Ref): Observer's own rows for tools it
	// captures. Every live source is experimental (undocumented endpoints).
	{ID: ProviderAutohand, Group: GroupPlans, Shows: sh(Shows5h, ShowsDaily, ShowsWeekly, ShowsMonthly), Tools: []string{"autohand"}},
	{ID: ProviderKimchi, Group: GroupBalance, Shows: sh(ShowsCredits, ShowsBudget), Tools: []string{"kimchi"}},
	{ID: ProviderStakpak, Group: GroupBalance, Shows: sh(ShowsCredits, ShowsMonthly), Tools: []string{"stakpak"}},
	// Cortex Code: the subscription quota arrives only on the inference
	// stream and stays in the CLI's memory; the per-user daily credit limit
	// is a Snowflake account parameter that needs Snowflake credentials.
	{ID: ProviderCortexCode, Group: GroupPlans, Shows: sh(ShowsDaily, ShowsCredits), Gap: GapCloudCredsOnly, Tools: []string{"cortex-code"}},
}

// ProviderByID returns the provider row.
func ProviderByID(id string) (ProviderDef, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return ProviderDef{}, false
}

// --- Derived coverage -----------------------------------------------------------

// Coverage is how far Observer can read a provider live, from the best
// source it has. Derived from the source table, never typed on a row.
type Coverage string

// Coverage values, best first.
const (
	CoverageOfficial     Coverage = "official"     // a documented route or Observer's own capture
	CoverageExperimental Coverage = "experimental" // another app's sign-in, local state or an undocumented endpoint
	CoverageSession      Coverage = "session"      // a browser session the user pastes
	CoverageManual       Coverage = "manual_only"  // no live source; typed plan facts only
)

// AllCoverages lists every coverage value, for vocabulary tests.
func AllCoverages() []Coverage {
	return []Coverage{CoverageOfficial, CoverageExperimental, CoverageSession, CoverageManual}
}

// coverageOfRung binds a rung to a coverage value (table, CLAUDE.md rule 5).
var coverageOfRung = map[Rung]Coverage{
	RungOfficial:     CoverageOfficial,
	RungExperimental: CoverageExperimental,
	RungBrowser:      CoverageSession,
}

// coverageRank orders coverage values, best first.
var coverageRank = map[Coverage]int{CoverageOfficial: 0, CoverageExperimental: 1, CoverageSession: 2, CoverageManual: 3}

// CoverageOf returns the best live coverage the provider's sources give. The
// manual source applies to every provider and does not count as live.
func CoverageOf(provider string) Coverage {
	best := CoverageManual
	for _, s := range Sources {
		if s.Provider != provider || s.Kind == KindManual {
			continue
		}
		if c, ok := coverageOfRung[s.Rung()]; ok && coverageRank[c] < coverageRank[best] {
			best = c
		}
	}
	return best
}

// AuthMethod is how a source gets at the vendor's numbers, in the words a
// person cares about: what they have to hand over, if anything.
type AuthMethod string

// Auth methods.
const (
	AuthNone          AuthMethod = "none"           // nothing to add: Observer's own capture
	AuthPastedKey     AuthMethod = "pasted_key"     // a key the user pastes, documented endpoint
	AuthUndocumented  AuthMethod = "undocumented"   // a key the user pastes, undocumented endpoint
	AuthVendorLocal   AuthMethod = "vendor_local"   // the vendor's own app or CLI on this machine, read-only
	AuthPastedSession AuthMethod = "pasted_session" // a browser session the user pastes
	AuthManual        AuthMethod = "manual"         // typed plan facts
)

// AllAuthMethods lists every auth method, for vocabulary tests.
func AllAuthMethods() []AuthMethod {
	return []AuthMethod{AuthNone, AuthPastedKey, AuthUndocumented, AuthVendorLocal, AuthPastedSession, AuthManual}
}

// authOfKind binds each source kind to its auth method (table, rule 5).
var authOfKind = map[SourceKind]AuthMethod{
	KindOfficialAPI:   AuthPastedKey,
	KindAdminAPI:      AuthPastedKey,
	KindStatusLine:    AuthNone,
	KindVendorRPC:     AuthVendorLocal,
	KindVendorCLI:     AuthVendorLocal,
	KindPassiveProxy:  AuthNone,
	KindPassiveLog:    AuthNone,
	KindManual:        AuthManual,
	KindLocalState:    AuthVendorLocal,
	KindBorrowedToken: AuthVendorLocal,
	KindUndocumented:  AuthUndocumented,
	KindBrowser:       AuthPastedSession,
}

// AuthOf returns the auth method of a source kind, "" when unknown.
func AuthOf(k SourceKind) AuthMethod { return authOfKind[k] }

// AuthMethodsOf returns the provider's auth methods in ladder order, without
// duplicates and without manual (every provider has it).
func AuthMethodsOf(provider string) []AuthMethod {
	var out []AuthMethod
	seen := map[AuthMethod]bool{}
	for _, s := range SourcesFor(provider) {
		a := AuthOf(s.Kind)
		if s.Kind == KindManual || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}
