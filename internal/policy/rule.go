package policy

import "fmt"

// Category groups rules for reporting, config filtering and the
// dashboard taxonomy (spec §4.3). G1 ships rules in
// CategoryDestructive and CategoryBoundary; the remaining categories
// are declared now so the vocabulary is stable for later commits.
type Category string

// Category values (spec §4.3).
const (
	// CategoryDestructive covers irreversible data/infrastructure
	// destruction (§5.1).
	CategoryDestructive Category = "destructive"
	// CategoryBoundary covers out-of-project access, sensitive
	// paths and persistence vectors (§5.2).
	CategoryBoundary Category = "boundary"
	// CategorySecrets covers secrets egress (§8.2, lands G9).
	CategorySecrets Category = "secrets"
	// CategoryExfil covers exfiltration/network shapes (§5.3).
	CategoryExfil Category = "exfil"
	// CategoryPosture covers risky client configuration (§5.4).
	CategoryPosture Category = "posture"
	// CategoryMCP covers MCP pinning/poisoning (§5.5, lands G10).
	CategoryMCP Category = "mcp"
	// CategoryInjection covers prompt-injection heuristics over
	// inbound tool-result/web content (§8.4, lands G9). Injection
	// rules NEVER deny (gap F7: heuristics gate blast-radius via
	// taint, not via claiming detection certainty).
	CategoryInjection Category = "injection"
	// CategoryTaint covers dataflow source→sink rules (§5.6, G3+).
	CategoryTaint Category = "taint"
	// CategoryBudget covers cost/token $ budgets (§5.7, lands G12).
	CategoryBudget Category = "budget"
	// CategoryLimit covers the provider's usage-window (5h / weekly)
	// utilization guardrails (§12.1). Distinct from CategoryBudget so
	// the [guard.budget].hard $-deny upgrade never touches them — a
	// util window carries its own explicit deny threshold.
	CategoryLimit Category = "limit"
	// CategoryAnomaly covers statistical anomaly rules (§5.7, G12).
	CategoryAnomaly Category = "anomaly"
	// CategoryPII covers deterministic PII detected in the
	// developer's OWN prompt text at submit-time — the prompt-submit
	// intervention feature (docs/plans/
	// prompt-submit-intervention-exploration-2026-09-07.md §5.6).
	// Distinct from CategoryExfil, which secret-shaped content in a
	// prompt or outbound request keeps (R-172, extended to
	// KindUserPrompt) — R-190 below is PII-only so the two categories
	// never collide on one rule ID (validateRules requires same-ID
	// rows to agree on category).
	CategoryPII Category = "pii"
)

// MatchContext is the per-evaluation working set, built ONCE by the
// engine and shared by every rule: command parsing and path
// normalization run a single time per Event, not once per rule
// (latency invariant §17.9).
type MatchContext struct {
	// Event is the event under evaluation.
	Event *Event
	// Cmds is the flattened, recursively-unwrapped command-unit
	// list for KindShellExec events (nil otherwise).
	Cmds []Command
	// Path is the resolved, normalized target path for
	// KindFileAccess events ("" otherwise, and "" when the target
	// could not be resolved — rules must treat "" as no-match,
	// never as a hit).
	Path string
	// Cfg is the engine configuration (Home, allowlists, protected
	// branches, known roots) shared with matchers read-only.
	Cfg *Config
}

// MatchFn is an event-scoped matcher: it inspects the whole
// MatchContext and reports whether the rule hits, plus a bounded
// human-readable detail naming the specific target/command for the
// verdict Reason. MatchFns must be pure and must not retain the
// context.
type MatchFn func(*MatchContext) (hit bool, detail string)

// MatchCmdFn is a command-unit-scoped matcher for shell rules. The
// ENGINE iterates command units and consults the rule's safe patterns
// per unit before calling this — the safe-pattern-first ordering is
// structural, a rule author cannot forget it (the dcg lesson, spec
// §4.3).
type MatchCmdFn func(ctx *MatchContext, cmd *Command) (hit bool, detail string)

// SafeFn is a safe-pattern predicate: true means the candidate is an
// explicitly-safe variant and the owning rule must NOT fire on it
// (e.g. `rm -rf /tmp/...`, `--force-with-lease`, `crontab -l`). For
// command-unit rules (MatchCmd set) the engine calls SafeFns once per
// unit with that unit; for event-scoped rules (Match set) it calls
// them once with cmd == nil.
type SafeFn func(ctx *MatchContext, cmd *Command) bool

// Rule is one ordered table row of the built-in policy (spec §4.3).
// Exactly one of Match / MatchCmd is set. A public rule ID may span
// several rows when the §5 catalog itself splits decision by
// sub-shape (approved deviation 3); same-ID rows must agree on
// Category and Severity (validated at engine construction).
type Rule struct {
	// ID is the stable public catalog ID ("R-101"). IDs are
	// documented, never reused, and stable across releases.
	ID string
	// Category groups the rule for reporting and config filtering.
	Category Category
	// Severity grades the rule independent of mode (a hit is
	// critical even while observe mode only flags it).
	Severity Severity
	// AppliesTo lists the event kinds this row evaluates.
	AppliesTo []EventKind
	// Match is the event-scoped matcher (file-access rows, and any
	// rule that needs the whole event). Nil when MatchCmd is set.
	Match MatchFn
	// MatchCmd is the command-unit-scoped matcher (shell rows). Nil
	// when Match is set.
	MatchCmd MatchCmdFn
	// Observe is the verdict decision in observe mode — the left
	// side of the §5 catalog's "observe → enforce" column (approved
	// deviation 2).
	Observe Decision
	// Enforce is the verdict decision in enforce mode — the right
	// side of the catalog column.
	Enforce Decision
	// SafePat are the rule's safe-variant predicates, evaluated by
	// the engine BEFORE the matcher (per command unit for MatchCmd
	// rows).
	SafePat []SafeFn
	// Doc is the catalog one-liner. It doubles as the Reason
	// prefix: Verdict.Reason = Doc + ": " + match detail.
	Doc string
	// Advice is the remediation hint carried on the verdict
	// ("Use --force-with-lease ...").
	Advice string
	// Source labels the policy layer the rule came from for verdict
	// attribution: "" (built-in tables — reported as SourceBuiltin),
	// "user", "project", "org". Compiled TOML rules (Config.
	// ExtraRules) set it; built-ins leave it empty.
	Source string
	// Enforced marks the rule per-rule-enforced (spec §4.1): its
	// enforce-mode decision applies even while the engine mode is
	// observe. Set via Override (the [[override]] enforce key) or on
	// compiled user rules with enforce = true.
	Enforced bool
}

// Override tunes rule rows by public ID without redefining them (spec
// §4.4 [[override]]). The guard composition layer enforces the §4.6
// one-way trust rules BEFORE constructing the engine — by the time an
// Override reaches policy.New it is mechanical: every row with the
// matching ID is rewritten. An Override naming an unknown rule ID is
// a construction error (loud, never a silent no-op).
type Override struct {
	// RuleID is the public rule ID the override targets ("R-110").
	RuleID string
	// Decision, when non-nil, replaces BOTH the observe-mode and
	// enforce-mode decisions of every row with this ID (a §4.4
	// override states one intended decision, not a mode pair).
	Decision *Decision
	// Enforced sets Rule.Enforced — the per-rule enforce upgrade.
	Enforced bool
	// Source labels the layer the override came from ("user",
	// "project", "org") so the verdict attributes to the layer that
	// last tuned the rule.
	Source string
}

// appliesTo reports whether the rule row evaluates events of kind k.
func (r *Rule) appliesTo(k EventKind) bool {
	for _, a := range r.AppliesTo {
		if a == k {
			return true
		}
	}
	return false
}

// validateRules checks the assembled rule tables once at engine
// construction (spec §17.5: a malformed table is a construction
// error, never a silent runtime no-op). It enforces: non-empty ID,
// category, doc and AppliesTo; exactly one of Match/MatchCmd;
// Enforce at least as strict as Observe (the catalog never relaxes
// under enforcement); and same-ID rows agreeing on Category and
// Severity.
func validateRules(rules []Rule) error {
	type idMeta struct {
		cat Category
		sev Severity
	}
	seen := make(map[string]idMeta, len(rules))
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			return fmt.Errorf("policy.validateRules: row %d has empty ID", i)
		}
		if r.Category == "" {
			return fmt.Errorf("policy.validateRules: %s has empty Category", r.ID)
		}
		if r.Doc == "" {
			return fmt.Errorf("policy.validateRules: %s has empty Doc", r.ID)
		}
		if len(r.AppliesTo) == 0 {
			return fmt.Errorf("policy.validateRules: %s has empty AppliesTo", r.ID)
		}
		if (r.Match == nil) == (r.MatchCmd == nil) {
			return fmt.Errorf("policy.validateRules: %s must set exactly one of Match/MatchCmd", r.ID)
		}
		if r.Enforce < r.Observe {
			return fmt.Errorf("policy.validateRules: %s enforce decision %q is weaker than observe %q", r.ID, r.Enforce, r.Observe)
		}
		if m, ok := seen[r.ID]; ok {
			if m.cat != r.Category || m.sev != r.Severity {
				return fmt.Errorf("policy.validateRules: %s rows disagree on category/severity", r.ID)
			}
		} else {
			seen[r.ID] = idMeta{cat: r.Category, sev: r.Severity}
		}
	}
	return nil
}
