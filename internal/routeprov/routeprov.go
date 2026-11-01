package routeprov

// Writer names who wrote, or last confirmed, a route.
type Writer string

// The writers. The zero value is "unknown": a write that did not say who it
// was is never treated as enrolment, so Leave keeps it.
const (
	// WriterEnrolment is `observer enroll --wire-clients` (the CLI enrol).
	WriterEnrolment Writer = "enrolment"
	// WriterInit is `observer init`, batch or interactive.
	WriterInit Writer = "init"
	// WriterSetup is the dashboard's Settings > Setup route buttons.
	WriterSetup Writer = "setup"
	// WriterLauncher is a tool launcher (`observer crush`, ...).
	WriterLauncher Writer = "launcher"
	// WriterManaged is the managed daemon's route maintenance (lane P1): on a
	// managed node the organization keeps AI tools routed through the
	// Observer proxy, so the daemon writes and repairs the route. Like
	// enrolment it is organization-owned: Leave removes it, and so does the
	// organization turning route maintenance off (Decide with OwnedBy).
	WriterManaged Writer = "managed"
)

// OrgOwned reports whether w is a writer that acted for the organization
// (enrolment, managed maintenance), whose routes Leave removes. Every other
// writer is the developer's own choice.
func OrgOwned(w Writer) bool { return w == WriterEnrolment || w == WriterManaged }

// FileVersion is the state file's schema version.
const FileVersion = 1

// Record is one route Observer wrote or confirmed, as it was at that moment.
type Record struct {
	// Tool is the route target label ("claude-code", "codex",
	// "claude-code-windows", ...), as proxyroute reports it.
	Tool string `json:"tool"`
	// ConfigPath is the absolute config file the route lives in.
	ConfigPath string `json:"config_path"`
	// Value is the route value written (the base URL).
	Value string `json:"value"`
	// Writer is who wrote it, or last confirmed it.
	Writer Writer `json:"writer"`
	// PriorProvider is Codex's top-level model_provider before the write
	// replaced it ("" when it was unset), so Leave can put it back.
	PriorProvider string `json:"prior_provider,omitempty"`
	// WrittenAt is when the record was made (RFC 3339, UTC).
	WrittenAt string `json:"written_at"`
	// RepairedAt is set (RFC 3339, UTC) when the managed daemon put this
	// route back after it had been removed: a record was already here and
	// the route was gone when the daemon looked. The managed-integrity probe
	// reports it as route_repaired for a day. A later write by any writer
	// replaces the record and so clears it.
	RepairedAt string `json:"repaired_at,omitempty"`
	// PriorBaseURL is the provider base URL the write replaced, when the
	// route rewrote one (a lane route for a third-party provider, Qwen
	// Code's default host), so removing the route puts that exact value
	// back. "" when the write only added a key.
	PriorBaseURL string `json:"prior_base_url,omitempty"`
	// RouteKey is the config path the route lives at, when it is not the
	// tool's fixed route key (a lane route on the provider entry the tool
	// actually uses), as path segments. Empty = the tool's fixed key.
	RouteKey []string `json:"route_key,omitempty"`
	// Lane / LaneRoot are the proxy `/up/<id>/` lane a lane route addresses
	// and the upstream host root that lane forwards to (the provider the
	// tool talked to before the route). A node-local route lane is
	// re-installed into the proxy from these at every start.
	Lane     string `json:"lane,omitempty"`
	LaneRoot string `json:"lane_root,omitempty"`
}

// sameRecord compares two records field by field (RouteKey is a slice).
func sameRecord(a, b Record) bool {
	if len(a.RouteKey) != len(b.RouteKey) {
		return false
	}
	for i := range a.RouteKey {
		if a.RouteKey[i] != b.RouteKey[i] {
			return false
		}
	}
	a.RouteKey, b.RouteKey = nil, nil
	return a.Tool == b.Tool && a.ConfigPath == b.ConfigPath && a.Value == b.Value && a.Writer == b.Writer &&
		a.PriorProvider == b.PriorProvider && a.WrittenAt == b.WrittenAt && a.RepairedAt == b.RepairedAt &&
		a.PriorBaseURL == b.PriorBaseURL && a.Lane == b.Lane && a.LaneRoot == b.LaneRoot
}

// File is the provenance state file.
type File struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// Find returns the record for a route target, or nil.
func (f *File) Find(tool, configPath string) *Record {
	for i := range f.Records {
		if f.Records[i].Tool == tool && f.Records[i].ConfigPath == configPath {
			return &f.Records[i]
		}
	}
	return nil
}

// Drop removes a route target's record (after Leave removed the route).
func (f *File) Drop(tool, configPath string) {
	out := f.Records[:0]
	for _, r := range f.Records {
		if r.Tool == tool && r.ConfigPath == configPath {
			continue
		}
		out = append(out, r)
	}
	f.Records = out
}

// Outcome is what a route writer did.
type Outcome int

// The write outcomes that matter for provenance.
const (
	// OutcomeNone is a dry run, an error or a skip: nothing is recorded.
	OutcomeNone Outcome = iota
	// OutcomeWrote: the writer set the route (it was absent or replaced).
	OutcomeWrote
	// OutcomeConfirmed: the route was already exactly this value.
	OutcomeConfirmed
)

// Note applies the claim rule for one write and reports whether the file
// changed. The rule, in order:
//
//  1. Nothing happened (OutcomeNone): no change.
//  2. The writer set the route: the record is the writer's, with this value.
//  3. The route was already this value and an organization-owned writer
//     (enrolment, managed maintenance) is the writer: no change. Neither
//     claims a route it found in place, so a route you or `observer init`
//     set before is kept on Leave.
//  4. The route was already this value and another writer confirmed it: the
//     record becomes that writer's. Someone chose this route on purpose
//     after enrolment wrote it, so Leave keeps it.
func (f *File) Note(rec Record, outcome Outcome) bool {
	switch {
	case outcome == OutcomeNone:
		return false
	case outcome == OutcomeConfirmed && OrgOwned(rec.Writer):
		return false
	}
	if cur := f.Find(rec.Tool, rec.ConfigPath); cur != nil {
		if outcome == OutcomeConfirmed {
			// A confirmation does not know what the original write replaced
			// or where it wrote; keep what is already recorded.
			rec.PriorProvider = cur.PriorProvider
			rec.PriorBaseURL = cur.PriorBaseURL
			rec.RouteKey = cur.RouteKey
			rec.Lane, rec.LaneRoot = cur.Lane, cur.LaneRoot
		}
		if sameRecord(*cur, rec) {
			return false
		}
		*cur = rec
		return true
	}
	f.Records = append(f.Records, rec)
	return true
}

// Action is what Leave does with one route.
type Action string

// The Leave actions.
const (
	// ActionRemove: Observer's enrolment wrote it and it is unchanged.
	ActionRemove Action = "remove"
	// ActionKeep: someone else set it, or it changed after enrolment.
	ActionKeep Action = "keep"
	// ActionNone: the route is not set; nothing to do.
	ActionNone Action = "none"
)

// Reason is why Decide chose its action.
type Reason string

// The Leave reasons.
const (
	ReasonNotSet              Reason = "not_set"
	ReasonNoRecord            Reason = "set_by_you"
	ReasonOtherWriter         Reason = "set_by_other_writer"
	ReasonChangedAfterEnrol   Reason = "changed_after_enrolment"
	ReasonWrittenByEnrolment  Reason = "written_by_enrolment"
	ReasonCannotRemoveForTool Reason = "cannot_remove_for_tool"
)

// Decision is Leave's verdict for one route target.
type Decision struct {
	Tool       string `json:"tool"`
	ConfigPath string `json:"config_path"`
	Current    string `json:"current,omitempty"`
	Action     Action `json:"action"`
	Reason     Reason `json:"reason"`
	Writer     Writer `json:"writer,omitempty"`
	// Message is the sentence the CLI prints and the Leave dialog shows.
	Message string `json:"message"`
}

// DecideInput is everything Decide needs for one route target.
type DecideInput struct {
	Tool       string
	ConfigPath string
	// Present / Current: whether the route is set now, and its value.
	Present bool
	Current string
	// Record is the provenance record for this target, or nil.
	Record *Record
	// Removable: proxyroute can undo this tool's route.
	Removable bool
	// Setting names the setting the route lives in ("ANTHROPIC_BASE_URL",
	// ...), resolved at the boundary from the integration registry's route
	// shape (integration.RouteSetting), so this package never branches on a
	// tool (T-495, CLAUDE.md rule 3). "" reads as "the Observer proxy route".
	Setting string
	// OwnedBy decides which writers' routes this pass may remove. Nil means
	// OrgOwned (leaving the organization removes enrolment's and managed
	// maintenance's routes); the organization turning route maintenance off
	// passes only WriterManaged.
	OwnedBy func(Writer) bool
}

// owned applies in.OwnedBy (default OrgOwned).
func (in DecideInput) owned(w Writer) bool {
	if in.OwnedBy != nil {
		return in.OwnedBy(w)
	}
	return OrgOwned(w)
}

type decideRule struct {
	match  func(in DecideInput) bool
	action Action
	reason Reason
}

// decideRules is the Leave table, walked top-down; the first match wins.
var decideRules = []decideRule{
	{func(in DecideInput) bool { return !in.Present }, ActionNone, ReasonNotSet},
	{func(in DecideInput) bool { return in.Record == nil }, ActionKeep, ReasonNoRecord},
	{func(in DecideInput) bool { return !in.owned(in.Record.Writer) }, ActionKeep, ReasonOtherWriter},
	{func(in DecideInput) bool { return in.Current != in.Record.Value }, ActionKeep, ReasonChangedAfterEnrol},
	{func(in DecideInput) bool { return !in.Removable }, ActionKeep, ReasonCannotRemoveForTool},
	{func(DecideInput) bool { return true }, ActionRemove, ReasonWrittenByEnrolment},
}

// Decide returns Leave's verdict for one route target.
func Decide(in DecideInput) Decision {
	d := Decision{Tool: in.Tool, ConfigPath: in.ConfigPath, Current: in.Current}
	if in.Record != nil {
		d.Writer = in.Record.Writer
	}
	for _, r := range decideRules {
		if r.match(in) {
			d.Action, d.Reason = r.action, r.reason
			break
		}
	}
	d.Message = message(d, in.Setting)
	return d
}

// toolLabels names a route target for people.
var toolLabels = map[string]string{
	"claude-code":         "Claude Code",
	"claude-code-windows": "Claude Code (Windows)",
	"codex":               "Codex",
	"codex-windows":       "Codex (Windows)",
	"kimi-code":           "Kimi Code",
	"qwen-code":           "Qwen Code",
	"crush":               "Crush",
}

// ToolLabel is the human name of a route target.
func ToolLabel(tool string) string {
	if l, ok := toolLabels[tool]; ok {
		return l
	}
	return tool
}

// writerPhrases says who set a route, for the "kept because" sentence.
var writerPhrases = map[Writer]string{
	WriterInit:     "`observer init` set it",
	WriterSetup:    "it was set from Settings > Setup",
	WriterLauncher: "a launcher set it",
	WriterManaged:  "your organization keeps it routed (it stays until the organization turns that off)",
}

// what names the setting a removal takes out: the boundary-resolved name,
// or a generic one when the registry grounds none.
func what(setting string) string {
	if setting != "" {
		return setting
	}
	return "the Observer proxy route"
}

func message(d Decision, setting string) string {
	label := ToolLabel(d.Tool)
	switch d.Reason {
	case ReasonWrittenByEnrolment:
		if d.Writer == WriterManaged {
			return "Removes " + what(setting) + " from " + d.ConfigPath + " (written because your organization keeps AI tools routed through the Observer proxy)."
		}
		return "Removes " + what(setting) + " from " + d.ConfigPath + " (written when this machine enrolled)."
	case ReasonNoRecord:
		return "Your " + label + " proxy setting will be kept because you set it yourself."
	case ReasonOtherWriter:
		if p, ok := writerPhrases[d.Writer]; ok {
			return "Your " + label + " proxy setting will be kept because " + p + "."
		}
		return "Your " + label + " proxy setting will be kept because you set it yourself."
	case ReasonChangedAfterEnrol:
		return "Your " + label + " proxy setting will be kept because it changed after enrolment wrote it."
	case ReasonCannotRemoveForTool:
		return "Enrolment wrote the " + label + " proxy route in " + d.ConfigPath + ", but Leave cannot undo this tool's route; remove it there by hand."
	}
	return ""
}
