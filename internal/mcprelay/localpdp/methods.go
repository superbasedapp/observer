package localpdp

import (
	"encoding/json"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
)

// methodParams is the subset of a JSON-RPC params object the dispatch table
// reads to find the addressed name (never the argument values).
type methodParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
	Ref  struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"ref"`
}

// methodSpec is one row of the dispatch table.
type methodSpec struct {
	Class  DecisionClass
	Action mcpaccess.Action
	// Target extracts the governed name; nil = the method addresses none.
	Target func(p methodParams) string
	// NameRequired refuses a governed request whose params carry no name.
	NameRequired bool
	// ToolScoped marks tools/call (name is a tool) and tools/list (visible
	// set is computed).
	ToolScoped bool
	// VisibleAction is the governed action a catalogue method advertises.
	VisibleAction mcpaccess.Action
	// Stripped marks a method the node relay refuses in v1 (R8.27.b): no
	// task-binding contract exists on the node, so tasks/* never forward.
	Stripped bool
}

func byName(p methodParams) string { return p.Name }
func byURI(p methodParams) string  { return p.URI }
func byRef(p methodParams) string {
	if p.Ref.URI != "" {
		return p.Ref.URI
	}
	return p.Ref.Name
}

// methods is the node dispatch table. It is the gateway PDP's table
// (internal/mcpgw/pdp/methods.go) with tasks/* marked Stripped; the parity
// test methods_test.go pins class + action equality for every shared method
// so the two never drift. Anything absent is refused with -32601 - never
// forwarded, in observe AND enforce.
var methods = map[string]methodSpec{
	"tools/call":            {Class: ClassGoverned, Action: mcpaccess.ActionCall, Target: byName, NameRequired: true, ToolScoped: true},
	"prompts/get":           {Class: ClassGoverned, Action: mcpaccess.ActionRead, Target: byName, NameRequired: true},
	"resources/read":        {Class: ClassGoverned, Action: mcpaccess.ActionRead, Target: byURI, NameRequired: true},
	"completion/complete":   {Class: ClassGoverned, Action: mcpaccess.ActionRead, Target: byRef, NameRequired: true},
	"tasks/get":             {Class: ClassGoverned, Action: mcpaccess.ActionTasksGet, Stripped: true},
	"tasks/update":          {Class: ClassGoverned, Action: mcpaccess.ActionTasksUpdate, Stripped: true},
	"tasks/cancel":          {Class: ClassGoverned, Action: mcpaccess.ActionTasksCancel, Stripped: true},
	"subscriptions/listen":  {Class: ClassGoverned, Action: mcpaccess.ActionSubscribe},
	"resources/subscribe":   {Class: ClassGoverned, Action: mcpaccess.ActionSubscribe, Target: byURI, NameRequired: true},
	"resources/unsubscribe": {Class: ClassGoverned, Action: mcpaccess.ActionSubscribe, Target: byURI, NameRequired: true},

	"tools/list":               {Class: ClassCatalogue, Action: mcpaccess.ActionList, ToolScoped: true, VisibleAction: mcpaccess.ActionCall},
	"prompts/list":             {Class: ClassCatalogue, Action: mcpaccess.ActionList, VisibleAction: mcpaccess.ActionRead},
	"resources/list":           {Class: ClassCatalogue, Action: mcpaccess.ActionList, VisibleAction: mcpaccess.ActionRead},
	"resources/templates/list": {Class: ClassCatalogue, Action: mcpaccess.ActionList, VisibleAction: mcpaccess.ActionRead},
	"server/discover":          {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"ping":                     {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"initialize":               {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"logging/setLevel":         {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},

	"notifications/initialized":        {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"notifications/cancelled":          {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"notifications/progress":           {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
	"notifications/roots/list_changed": {Class: ClassCatalogue, Action: mcpaccess.ActionDiscover},
}

// Methods returns the dispatch table's method names, sorted.
func Methods() []string {
	out := make([]string, 0, len(methods))
	for m := range methods {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// MethodClass reports the decision class, grant action and stripped flag of
// method, and whether it is dispatched at all.
func MethodClass(method string) (class DecisionClass, action mcpaccess.Action, stripped, known bool) {
	s, ok := methods[method]
	if !ok {
		return "", "", false, false
	}
	return s.Class, s.Action, s.Stripped, true
}

// decodeParams reads the addressed-name fields of params; a malformed
// params object is reported, an absent one is empty.
func decodeParams(raw json.RawMessage) (methodParams, bool) {
	var p methodParams
	if len(raw) == 0 || string(raw) == "null" {
		return p, true
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, false
	}
	return p, true
}
