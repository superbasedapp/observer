package main

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// help.go: the user-facing Settings help (U-14, Plane A UI review
// 2026-11-21). Settings used to show each key's raw Go doc comment
// ("ObservabilityConfig is the [observability] surface (admission spec
// §4).") in every section. The doc comment stays the developer's record
// (Leaf.Doc / Table.Doc, the hover text for a curious reader); Help is what
// a person reads under a setting. It is derived from the doc by the ordered
// rewrite rules below, and helpOverrides replaces it outright where the
// derived text still reads like a design note. Pure: no I/O, deterministic.

// helpRule is one ordered rewrite of a doc comment into help.
type helpRule struct {
	name string
	// re matches the text to rewrite; repl is its replacement.
	re   *regexp.Regexp
	repl string
}

// internalRef is a parenthetical that only points at design records: a
// spec section, a plan, lane, ticket, decision or rule id. Such a
// parenthetical tells a Settings reader nothing.
const internalRef = `§|\b(?:plan|spec|lane|decision|decisions|audit|ruling|ADR|item|review|wave|contract|section|sections|rules?|Q\d+)\b|\b[A-Z][A-Z0-9]{0,6}-[A-Z0-9]*\d+[a-z]?\b|\b[A-Z]{1,3}\d+(?:\.\d+)?\b`

// helpRules is walked top to bottom on the doc with its leading Go
// identifier already removed (helpSubject).
var helpRules = []helpRule{
	// "(decision SBXD-8, audit item H8)", "(plan §8)", "(rules B-604 /
	// B-603)": design-record pointers, dropped with their leading space.
	{name: "internal_parenthetical", re: regexp.MustCompile(`\s*\((?:[^()]*?(?:` + internalRef + `)[^()]*?)\)`), repl: ""},
	// "(see database/sql.DB.SetConnMaxIdleTime)", "(Engine.ObserveTurn)":
	// a pointer into Go code.
	{name: "code_parenthetical", re: regexp.MustCompile(`\s*\((?:see\s[^()]*|[^()]*\b[A-Za-z_]\w*\.[A-Z]\w*\b[^()]*)\)`), repl: ""},
	// "[JSP-2]": a bracketed ticket id (a [toml.table] has no capitals).
	{name: "bracket_ref", re: regexp.MustCompile(`\s*\[[A-Z][A-Z0-9]*-[A-Z0-9.-]+\]`), repl: ""},
	// A bare section reference left outside a parenthetical.
	{name: "bare_section", re: regexp.MustCompile(`\s*§[A-Za-z0-9.]+`), repl: ""},
	// "one of SecurityPostWriteCapsKiB": the Go list that holds the
	// choices; Settings shows the choices themselves.
	{name: "go_choice_list", re: regexp.MustCompile(`[,:;]?\s*(?:one of|from|see)\s+[A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9]*)+\b`), repl: ""},
	// Doubled spaces and a space before punctuation, left by the drops.
	{name: "spaces", re: regexp.MustCompile(`\s{2,}`), repl: " "},
	{name: "space_before_punct", re: regexp.MustCompile(`\s+([.,;:])`), repl: "$1"},
	// "the X;." or ":." left when a clause was dropped at the end.
	{name: "dangling_punct", re: regexp.MustCompile(`[,;:]\s*\.`), repl: "."},
}

// leadingCopula is "is the X" / "are X" after the subject: dropped, so the
// help starts with what the setting is.
var leadingCopula = regexp.MustCompile(`^(?:is|are)\s+`)

// quotedLabel is `"Secret check before writes": ...`, a doc that opens with
// the setting's own UI label.
var quotedLabel = regexp.MustCompile(`^"([^"]+)":\s*`)

// tableSubject is "the [observer.process] surface — ...", "[guard.budget]."
// or "[guard.budget.window] — ...": the TOML table naming itself, which the
// Settings section already shows.
var tableSubject = regexp.MustCompile(`^(?:the\s+)?\[[a-z0-9_.-]+\](?:\s+(?:surface|section|table|block))?\s*(?:—|–|-|:|,|\.)?\s*`)

// leadingParenthetical is a parenthetical right after the subject.
var leadingParenthetical = regexp.MustCompile(`^\([^()]*\)\s*`)

// userHelp turns doc, the Go doc comment of the field or type named ident,
// into Settings help: the Go identifier and design-record pointers removed,
// one paragraph, starting with a capital. "" when nothing readable is left.
func userHelp(doc, ident string) string {
	s := strings.Join(strings.Fields(doc), " ")
	if s == "" {
		return ""
	}
	s = helpSubject(s, ident)
	s = leadingParenthetical.ReplaceAllString(s, "")
	s = leadingCopula.ReplaceAllString(s, "")
	label := ""
	if m := quotedLabel.FindStringSubmatch(s); m != nil {
		label = m[1]
		s = s[len(m[0]):]
	}
	for _, r := range helpRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	s = tableSubject.ReplaceAllString(strings.TrimSpace(s), "")
	s = strings.TrimLeft(s, ".,;:—–- ")
	if !hasWords(s) {
		s = ""
	}
	// A doc that opened with the setting's own label keeps it as the first
	// sentence.
	if label != "" {
		if !strings.HasSuffix(label, ".") {
			label += "."
		}
		s = strings.TrimSpace(label + " " + capitalize(s))
	}
	return capitalize(s)
}

// helpSubject drops the leading Go identifier a doc comment opens with
// ("RetentionConfig controls ...", "WeeklyUSD / MonthlyUSD are ...").
func helpSubject(s, ident string) string {
	if ident == "" {
		return s
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(ident) + `(?:\s*(?:/|,|and|or)\s*[A-Z][A-Za-z0-9]*)*\b\s*`)
	return re.ReplaceAllString(s, "")
}

// hasWords reports whether s still says something (two letters or more).
func hasWords(s string) bool {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
			if n >= 2 {
				return true
			}
		}
	}
	return false
}

// capitalize upper-cases the first letter of s.
func capitalize(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}

// helpOverrides is user-facing help written by hand, keyed by the dotted
// path of a table or a leaf. It wins over the derived help. It covers the
// sections whose derived help still read like a design note, starting with
// AI Apps (the [observability] keys, U-14 and its "hosted app's spans"
// wording). Every key must name a real table or leaf
// (TestHelpOverridesNameRealKeys).
var helpOverrides = map[string]string{
	"observability":                     "AI Apps: receive traces from the apps you build with the superbased SDKs or OpenTelemetry, and keep them on this machine.",
	"observability.enabled":             "Turns AI Apps on: this machine receives your apps' traces and shows them on the AI Apps pages.",
	"observability.eval":                "Evals: score your apps' traces as they arrive, or run scorers over a dataset.",
	"observability.judge":               "The LLM judge that evals use: an OpenAI-compatible chat completions endpoint.",
	"observability.admission":           "Admission: check each request your app sends before it reaches the model, then allow, flag, ask or deny it.",
	"observability.admission.judge":     "The LLM judge that admission uses for the criteria that need one.",
	"observability.admission.prefilter": "Fast checks that run before the judge: allow and deny patterns, and a size limit.",
	"observability.admission.budget":    "Spend limits for each end user of your app, checked before a request reaches the model.",
	"observability.alerts":              "Alerts on your apps' traces, sent from this machine.",
	"observability.sdk":                 "Where the superbased SDKs send an app's data when the app does not choose.",

	"observability.store_content":                         "Keep the prompts, responses and tool inputs of your apps' traces on this machine, with secrets removed. Off keeps only their fingerprints and the traces' timings, models and token counts.",
	"observability.eval.online_sample_rate":               "The share of your apps' model calls scored as they arrive, from 0 (off, the default) to 1 (every call).",
	"observability.eval.online_scorers":                   "The scorers run on the sampled calls, by name. Scorers that read only the trace's facts suit live scoring best.",
	"observability.eval.judge_model":                      "The model an LLM judge scorer uses. Empty turns the LLM judge off.",
	"observability.eval.judge_base_url":                   "The OpenAI-compatible address the judge calls. Empty uses OpenRouter.",
	"observability.eval.judge_api_key_env":                "The name of the environment variable that holds the judge's API key. The key itself is never stored.",
	"observability.judge.model":                           "The judge model. Empty turns the judge off.",
	"observability.judge.base_url":                        "The OpenAI-compatible address the judge calls. Empty uses OpenRouter.",
	"observability.judge.api_key_env":                     "The name of the environment variable that holds the judge's API key. The key itself is never stored. A judge on this machine needs none.",
	"observability.admission.enabled":                     "Turns admission on: requests your app sends through this machine are checked before they reach the model.",
	"observability.admission.mode":                        "Off, observe (record each decision, never block) or enforce (apply it). Empty means observe while admission is on.",
	"observability.admission.strict":                      "Deny a request when the judge fails or times out. Off allows it and records the error. The judge error setting says the same more clearly and wins when set.",
	"observability.admission.on_judge_error":              "What happens when the judge cannot answer: allow the request (fail open) or deny it (fail closed).",
	"observability.admission.scope":                       "What the judge reads: the last user message (the default) or the whole conversation.",
	"observability.admission.retention_days":              "How many days admission decisions are kept on this machine. 0 keeps them.",
	"observability.admission.criterion":                   "The criteria every request is checked against. Edit them on the Policies page.",
	"observability.admission.secret_remote_judge":         "The decision when a request carries a secret and the judge runs off this machine. The request is never sent to that judge.",
	"observability.admission.include_reasoning":           "Ask the judge to explain each decision. Slower, so off by default.",
	"observability.admission.budget.enabled":              "Turns the per-user spend limits on.",
	"observability.admission.budget.per_user_5h_usd":      "Each end user's spend limit over 5 hours, in dollars. 0 is no limit.",
	"observability.admission.budget.per_user_weekly_usd":  "Each end user's spend limit over a week, in dollars. 0 is no limit.",
	"observability.admission.budget.per_user_monthly_usd": "Each end user's spend limit over a month, in dollars. 0 is no limit.",
	"observability.admission.budget.user_header":          "The request header your app puts each end user's id in, so limits apply per user.",
	"observability.admission.prefilter.allow":             "Patterns that let a request through without asking the judge.",
	"observability.admission.prefilter.deny":              "Patterns that deny a request without asking the judge.",
	"observability.admission.prefilter.max_message_bytes": "The longest message allowed, in bytes: a longer one is denied without asking the judge. 0 is no limit.",
	"observability.alerts.enabled":                        "Turns alerts on. Off by default, because a fired alert can send data to a webhook.",
	"observability.alerts.webhook_url":                    "The address each fired alert is posted to. Empty records alerts on this machine and sends nothing.",
	"observability.alerts.email":                          "Also email each fired alert, through this machine's email settings (which must be on).",
	"observability.alerts.email_to":                       "Who gets alert emails. Empty uses the recipients in this machine's email settings.",
	"observability.alerts.eval_interval_minutes":          "How often alert rules are checked, in minutes. 0 means every 5.",
	"observability.alerts.slack_webhook_url":              "A Slack incoming webhook each fired alert is posted to. Kept secret: never shown after it is saved.",
	"observability.alerts.pagerduty_routing_key":          "A PagerDuty routing key: a fired alert opens an incident and its clear resolves it. Kept secret: never shown after it is saved.",
	"observability.alerts.rules":                          "The alert rules this machine checks.",
	"observability.egress.enabled":                        "Turns model routing for your apps' requests on.",
	"observability.egress.mode":                           "Off, advise (record where a request would go, change nothing) or enforce (route it).",
	"observability.egress.cooldown_seconds":               "How long a conversation stays on a model after a cost switch, in seconds.",
	"observability.egress.rules":                          "The routing rules, checked in order; the first match wins.",
	"observability.egress.targets":                        "The model endpoints a rule can route to.",
	"observability.egress.cohorts":                        "Groups of end users that rules can name. Kept on this machine.",

	"selfobs":                  "Self-monitoring: send a record of this machine's own decisions, such as admission and model routing, as traces to your team's gateway. Off by default.",
	"selfobs.enabled":          "Turns self-monitoring on. It also needs the gateway address and a credential; nothing is sent without them.",
	"selfobs.endpoint":         "The gateway address the records go to, as host:port or a full URL.",
	"selfobs.key_id":           "The id half of the gateway credential, used with the secret. A token wins when both are set.",
	"selfobs.secret":           "The secret half of the gateway credential. Set it in the config file; it is never shown here.",
	"selfobs.token":            "A gateway token to use instead of the id and secret. Set it in the config file; it is never shown here.",
	"selfobs.insecure":         "Allow a plain http:// gateway address. Off requires https://.",
	"selfobs.service_name":     "The service name the records carry. Empty uses superbased-observer.",
	"selfobs.routing_sample_n": "How many model-routing decisions are sent: 0 sends none, 1 sends every one, and N sends one in N. The default is 32.",
}

// helpFor is a table's or a leaf's help: the override, else the derived
// help.
func helpFor(path, doc, ident string) string {
	if h, ok := helpOverrides[path]; ok {
		return h
	}
	return userHelp(doc, ident)
}
