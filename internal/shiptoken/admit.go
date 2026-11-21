package shiptoken

import (
	"reflect"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Binding is the identity a ship token was minted for. Every row a
// ship-token batch lands is attributed to it; nothing in the envelope can
// name another member or another machine.
type Binding struct {
	// UserID is the member (org) the token ships for. Empty on a node.
	UserID string
	// MachineIdentity is the member's managed node machine the token is
	// bound to, "" for a member-level (BYO) subject. The envelope's own
	// machine_identity is always replaced by it.
	MachineIdentity string
}

// admittedFamilies is the closed allow-list of push-envelope families (by
// JSON name) a ship-token batch may land. They are the SESSION-SCOPED
// capture families a sandbox's own agent session produces. Everything else
// is dropped with a count:
//
//   - deletions and session_manifests: a sandbox must never delete or heal
//     away rows of the member's real node;
//   - every node posture or inventory field (update, budget, component,
//     sandbox, security, agent config, MCP inventory, guard pins): a sandbox
//     is not a node and must not appear as one or overwrite one;
//   - per-node and per-day aggregates (routing, cache, codeintel, process,
//     LOC days, delivery, pull requests, commit ownership, compression,
//     benchmarks, advisor, patterns): keyed by the member's node, so a
//     sandbox's copy would overwrite the node's;
//   - Plane A (obs_*), terminals, remote audit, guard events, MCP relay,
//     change records, limit gauges, processes (session_processes and its
//     capture-budget companions session_process_rollups and
//     session_process_capture_stats, which only describe runs the node's
//     process capture counted), network events: not produced by a sandbox
//     capture, and each carries node-bound semantics.
//
// A new envelope family is dropped until a row is added here
// (TestEveryEnvelopeFamilyClassified).
var admittedFamilies = map[string]bool{
	"sessions":                 true,
	"actions":                  true,
	"api_turns":                true,
	"token_usage":              true,
	"session_loc":              true,
	"session_quality":          true,
	"session_verbosity":        true,
	"session_cache":            true,
	"session_cache_events":     true,
	"session_task_items":       true,
	"session_task_transitions": true,
	"session_tool_accounts":    true,
	"session_hook_activity":    true,
	"otel_content":             true,
}

// keptScalars are the envelope's non-family fields a ship-token batch keeps
// as sent: the agent version (it travels with rows, never onto the version
// board, because the ship-token ingest skips every inventory write) and the
// two cursor fields the destination echoes back.
var keptScalars = map[string]bool{
	"agent_version": true,
	"cursor_from":   true,
	"cursor_to":     true,
}

// forcedScalars are the envelope's identity fields Admit overwrites from the
// Binding (machine_identity) or clears (source_node_key: a sandbox holds no
// node key, so the destination derives the member-keyed compat value).
var forcedScalars = map[string]bool{
	"machine_identity": true,
	"source_node_key":  true,
}

// AdmittedFamilies returns the allow-list, sorted (for docs and tests).
func AdmittedFamilies() []string {
	out := make([]string, 0, len(admittedFamilies))
	for k := range admittedFamilies {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Execution-location outcomes of one session row (Admitted.Execution).
const (
	ExecKept    = "kept"
	ExecUnknown = "unknown"
	ExecRefused = "refused_local"
	ExecInvalid = "invalid"
)

// executionRule is one row of the execution-location table.
type executionRule struct {
	name    string
	match   func(loc string) bool
	outcome string
	land    func(loc string) string
}

// executionRules decide each session row's execution_location, top-down.
// The batch arrived on the cloud-session route, so a row that says it ran
// locally contradicts the route and lands unknown rather than local; an
// absent value stays unknown (never a defaulted guess), and a value outside
// the closed vocabulary lands unknown as the ordinary ingest would.
var executionRules = []executionRule{
	{"absent stays unknown", func(l string) bool { return l == "" }, ExecUnknown, func(string) string { return "" }},
	{"local contradicts the route", func(l string) bool { return l == models.ExecutionLocal }, ExecRefused, func(string) string { return "" }},
	{"a known remote location is kept", models.KnownExecutionLocation, ExecKept, func(l string) string { return l }},
	{"anything else is invalid", func(string) bool { return true }, ExecInvalid, func(string) string { return "" }},
}

// ResolveExecution applies the execution table to one pushed value.
func ResolveExecution(loc string) (landed, outcome string) {
	loc = strings.TrimSpace(loc)
	for _, r := range executionRules {
		if r.match(loc) {
			return r.land(loc), r.outcome
		}
	}
	return "", ExecInvalid
}

// Admitted is the result of Admit.
type Admitted struct {
	// Envelope holds only the admitted families, the kept scalars and the
	// binding's identity.
	Envelope orgcontract.PushEnvelope
	// Dropped counts the rows of each dropped family (by JSON name); a
	// pointer field counts as one row. Empty families are not listed.
	Dropped map[string]int
	// Execution counts session rows per execution outcome.
	Execution map[string]int
	// Rows is the number of admitted rows.
	Rows int
}

// DroppedTotal sums Dropped.
func (a Admitted) DroppedTotal() int {
	n := 0
	for _, v := range a.Dropped {
		n += v
	}
	return n
}

// Admit filters env through the admission table and binds it to b. It never
// mutates env.
func Admit(env orgcontract.PushEnvelope, b Binding) Admitted {
	out := Admitted{Dropped: map[string]int{}, Execution: map[string]int{}}
	src := reflect.ValueOf(env)
	dst := reflect.ValueOf(&out.Envelope).Elem()
	t := src.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := jsonName(f)
		v := src.Field(i)
		switch {
		case admittedFamilies[name]:
			dst.Field(i).Set(copyValue(v))
			out.Rows += rowCount(v)
		case keptScalars[name]:
			dst.Field(i).Set(v)
		case forcedScalars[name]:
			// Set from the binding below.
		default:
			if n := rowCount(v); n > 0 {
				out.Dropped[name] += n
			}
		}
	}
	out.Envelope.MachineIdentity = strings.TrimSpace(b.MachineIdentity)
	out.Envelope.SourceNodeKey = ""
	for i := range out.Envelope.Sessions {
		landed, outcome := ResolveExecution(out.Envelope.Sessions[i].ExecutionLocation)
		out.Envelope.Sessions[i].ExecutionLocation = landed
		out.Execution[outcome]++
	}
	return out
}

// familyRows counts the rows of one envelope family (by JSON name).
func familyRows(env orgcontract.PushEnvelope, family string) int {
	v := reflect.ValueOf(env)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if jsonName(t.Field(i)) == family {
			return rowCount(v.Field(i))
		}
	}
	return 0
}

// jsonName is a struct field's JSON key.
func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return f.Name
	}
	return name
}

// rowCount counts the rows a field carries: a slice's length, one for a
// non-nil pointer, zero for anything else.
func rowCount(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Slice:
		return v.Len()
	case reflect.Pointer:
		if v.IsNil() {
			return 0
		}
		return 1
	default:
		return 0
	}
}

// copyValue returns a shallow copy of a slice (so Admit's later edits to
// session rows never reach the caller's envelope) or v itself.
func copyValue(v reflect.Value) reflect.Value {
	if v.Kind() != reflect.Slice || v.IsNil() {
		return v
	}
	c := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
	reflect.Copy(c, v)
	return c
}
