package localpdp

import (
	"fmt"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
)

// Compile builds the node Table from a verified tools.mcp_access spec (the
// four-gate accept's PolicyResourceResult.Spec) and its Meta. now is the
// unix-seconds instant expired grants are dropped at. The effective mode is
// the body's mode lowered to observe when meta.EnforceAllowed is false
// (PRAppliedInert): a node never enforces a body it did not preauthorize.
func Compile(spec famcp.PolicySpec, meta Meta, now int64) (*Table, error) {
	node, err := mcpaccess.CompileNodeTable(spec.Spec, now)
	if err != nil {
		return nil, fmt.Errorf("localpdp.Compile: %w", err)
	}
	mode := ModeObserve
	if famcp.Enforces(spec) && meta.EnforceAllowed {
		mode = ModeEnforce
	}
	return newTable(node, mode, meta), nil
}

// newTable finishes a Table: mode, meta and the grant index.
func newTable(node mcpaccess.NodeDecisionTable, mode Mode, meta Meta) *Table {
	t := &Table{Meta: meta, Mode: mode, Node: node, Grants: make(map[string]mcpaccess.Grant, len(node.Rows))}
	for _, r := range node.Rows {
		t.Grants[r.Grant.ID] = r.Grant
	}
	return t
}

// PolicyGen is the registry's policy generation.
func (t *Table) PolicyGen() int64 { return t.Node.Registry.PolicyGen }

// Holder is the hot-swappable current table (one owner: whoever wires the
// relay swaps a freshly compiled table in on every applied poll). A nil
// current table is "no policy loaded" - the engine refuses every call.
type Holder struct {
	cur atomic.Pointer[Table]
}

// Current returns the current table or nil.
func (h *Holder) Current() *Table {
	if h == nil {
		return nil
	}
	return h.cur.Load()
}

// Swap installs t (nil clears) and returns the previous table.
func (h *Holder) Swap(t *Table) *Table { return h.cur.Swap(t) }

// NodeIdentity is the enrolled node's own identity for a TOKEN-LESS local
// stdio call (no exchanged at+jwt in hand). The four-gate accept verified
// the table under this same enrolment, so asserting it here rides the same
// trust; the require invariants (issuer / org / audience / policy_gen) are
// then satisfied from the table's own registry, which is honest for a
// call that never crossed a token boundary.
type NodeIdentity struct {
	Subject   string
	MemberID  string
	MachineFP string
	ClientID  string
	Product   string
	AgentKind string
	Env       string
	Workspace string
	Groups    []string
	// CredAssurance defaults to node_enrolled when empty.
	CredAssurance string
}

// NodePrincipal builds the principal for a token-less local call against
// vserver, in the table's registry vocabulary. transport is what the relay
// observed. ok is false when the vserver is unknown to the table (the
// engine would deny it anyway; callers may short-circuit).
func (t *Table) NodePrincipal(id NodeIdentity, vserver string, transport Transport) (Principal, bool) {
	v, ok := t.Node.Registry.VServerByID(vserver)
	if !ok {
		return Principal{}, false
	}
	cred := id.CredAssurance
	if cred == "" {
		cred = "node_enrolled"
	}
	return Principal{
		Issuer:            t.Node.Registry.Issuer,
		Org:               t.Node.Registry.Org,
		Audience:          []string{t.Node.Registry.AudienceOf(v)},
		PolicyGen:         t.Node.Registry.PolicyGen,
		Subject:           id.Subject,
		MemberID:          id.MemberID,
		MachineFP:         id.MachineFP,
		ClientID:          id.ClientID,
		Product:           id.Product,
		AgentKind:         id.AgentKind,
		Env:               id.Env,
		Workspace:         id.Workspace,
		Groups:            append([]string(nil), id.Groups...),
		CredAssurance:     cred,
		ClientAttestation: AttestationFor(transport),
		Transport:         transport,
	}, true
}
