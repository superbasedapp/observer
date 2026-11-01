package govern

// routeposture.go: who decides whether a managed node keeps its AI tools
// routed through the Observer proxy (lane P1).
//
// Operator ruling 2026-10-18: "proxy routing at managed node is a fully
// configurable setting by admin in their org observer admin dashboard UI.
// They can set it or remove it at their discretion." The admin's setting is
// the node.governance settings.pin key MaintainRoutesKey, authored on the
// node-governance policy form and signed like every other pin. Composition,
// in this order (routePostureRules, one test case per row):
//
//  1. Not a managed node, or its grant is refused: no route posture at all.
//     An individual node is never rewritten.
//  2. The admin pinned the setting ON: maintain (write and repair routes).
//  3. The admin pinned the setting OFF: release (stop maintaining and remove
//     exactly the routes the organization wrote, like leaving it).
//  4. Unset: the enforce authorities are the DEFAULT. An organization that
//     governs an enforcement point living in the API proxy
//     (RequiresProxyRoute) gets maintain.
//  5. Otherwise: no route posture (nothing is written, nothing removed).

// MaintainRoutesKey is the node.governance pinnable key the admin uses to
// turn managed route maintenance on or off (internal/policyfam/nodegov
// PinnableKeys row "proxy.maintain_routes").
const MaintainRoutesKey = "proxy.maintain_routes"

// RoutePosture is what a managed node does about AI tool proxy routes.
type RoutePosture string

const (
	// RoutePostureNone: leave tool configs alone.
	RoutePostureNone RoutePosture = "none"
	// RoutePostureMaintain: keep every routable AI tool routed through the
	// Observer proxy and put a removed route back.
	RoutePostureMaintain RoutePosture = "maintain"
	// RoutePostureRelease: remove the routes the organization wrote and stop
	// maintaining them.
	RoutePostureRelease RoutePosture = "release"
)

// RoutePostureSource says which rule decided the posture.
type RoutePostureSource string

const (
	// RoutePostureSourceNotManaged: rule 1, not a managed node.
	RoutePostureSourceNotManaged RoutePostureSource = "not_managed"
	// RoutePostureSourceAdminOn: rule 2, the admin turned it on.
	RoutePostureSourceAdminOn RoutePostureSource = "admin_on"
	// RoutePostureSourceAdminOff: rule 3, the admin turned it off.
	RoutePostureSourceAdminOff RoutePostureSource = "admin_off"
	// RoutePostureSourceEnforceDefault: rule 4, unset, and the org governs
	// an enforcement point in the API proxy.
	RoutePostureSourceEnforceDefault RoutePostureSource = "enforce_default"
	// RoutePostureSourceNotRequired: rule 5, unset and not required.
	RoutePostureSourceNotRequired RoutePostureSource = "not_required"
)

// RoutePostureVerdict is the resolved posture and the rule behind it.
type RoutePostureVerdict struct {
	Posture RoutePosture
	Source  RoutePostureSource
}

type routePostureInput struct {
	managed  bool
	pinned   bool
	value    bool
	required bool
}

type routePostureRule struct {
	match   func(in routePostureInput) bool
	posture RoutePosture
	source  RoutePostureSource
}

var routePostureRules = []routePostureRule{
	{func(in routePostureInput) bool { return !in.managed }, RoutePostureNone, RoutePostureSourceNotManaged},
	{func(in routePostureInput) bool { return in.pinned && in.value }, RoutePostureMaintain, RoutePostureSourceAdminOn},
	{func(in routePostureInput) bool { return in.pinned }, RoutePostureRelease, RoutePostureSourceAdminOff},
	{func(in routePostureInput) bool { return in.required }, RoutePostureMaintain, RoutePostureSourceEnforceDefault},
	{func(routePostureInput) bool { return true }, RoutePostureNone, RoutePostureSourceNotRequired},
}

// RoutePosture resolves this node's route posture (the rules above). A
// pinned value that is not a bool reads as unset (the vocabulary only ever
// distributes a bool for this key).
func (e Effective) RoutePosture() RoutePostureVerdict {
	in := routePostureInput{managed: e.Managed && !e.GrantRefused(), required: e.RequiresProxyRoute()}
	if v, ok := e.IsPinned(MaintainRoutesKey); ok {
		if b, isBool := v.(bool); isBool {
			in.pinned, in.value = true, b
		}
	}
	for _, r := range routePostureRules {
		if r.match(in) {
			return RoutePostureVerdict{Posture: r.posture, Source: r.source}
		}
	}
	return RoutePostureVerdict{Posture: RoutePostureNone, Source: RoutePostureSourceNotRequired}
}
