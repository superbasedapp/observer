package cloudagents

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Grounding is the connector-level coverage level of decision CA-D17: how
// well the vendor surface a connector reads is established, as opposed to
// the per-account, per-signal CoverageState. It answers "how far can I
// trust that this connector reads the vendor correctly?", before any
// account is linked.
type Grounding string

// The closed grounding vocabulary, best first (the order of groundingLevels).
const (
	// GroundingVerified: a live run against a signed-in account passed for
	// this connector ("Live verified").
	GroundingVerified Grounding = "live_verified"
	// GroundingDocumented: built from the vendor's published documentation
	// and not yet confirmed by a live run (CA-D17's default).
	GroundingDocumented Grounding = "documented"
	// GroundingObservedUndocumented: the vendor publishes no API for the
	// surface; it is read from the vendor's own client code (operator
	// ruling C6 Q2, 2026-11-01).
	GroundingObservedUndocumented Grounding = "observed_undocumented"
)

// GroundingLevel is one row of the grounding table.
type GroundingLevel struct {
	Level Grounding
	// Label is the user-facing name.
	Label string
	// Meaning is what the level tells a user, in one or two sentences.
	Meaning string
	// RequiresDriftTest: a connector at this level must carry a
	// schema-drift test for every vendor surface it reads (driftTests,
	// pinned by TestUndocumentedConnectorsCarryDriftTests).
	RequiresDriftTest bool
	// Ledger names the docs/security.md ledger row that records the level's
	// risk ("" for none).
	Ledger string
}

// groundingLevels is the grounding table, best first; a level's rank is its
// index. A new level is a row here, never a special case at a call site.
var groundingLevels = []GroundingLevel{
	{
		Level: GroundingVerified, Label: "Live verified",
		Meaning: "A live run against a signed-in account confirmed what this connector reads.",
	},
	{
		Level: GroundingDocumented, Label: "Documented",
		Meaning: "Built from the vendor's published documentation; not yet confirmed by a live run.",
	},
	{
		Level: GroundingObservedUndocumented, Label: "Observed in vendor client, undocumented",
		Meaning: "The vendor publishes no API for this; Observer reads what the vendor's own app uses. " +
			"It can change or stop working without notice, and a change shows as a wrong_shape error, never as wrong numbers.",
		RequiresDriftTest: true, Ledger: "UNDOCSURF-1",
	},
}

// GroundingLevels returns the grounding table (a copy), best first.
func GroundingLevels() []GroundingLevel {
	return append([]GroundingLevel(nil), groundingLevels...)
}

// LevelOf returns the grounding table row of g (false for an unknown level).
func LevelOf(g Grounding) (GroundingLevel, bool) {
	for _, l := range groundingLevels {
		if l.Level == g {
			return l, true
		}
	}
	return GroundingLevel{}, false
}

// Rank is g's position in the table, 0 the best; an unknown level ranks
// below every known one.
func (g Grounding) Rank() int {
	for i, l := range groundingLevels {
		if l.Level == g {
			return i
		}
	}
	return len(groundingLevels)
}

// Label is the user-facing name of g ("" for an unknown level).
func (g Grounding) Label() string {
	l, _ := LevelOf(g)
	return l.Label
}

// connectorGrounding is one connector's grounding level and the evidence
// for it.
type connectorGrounding struct {
	connector string
	level     Grounding
	evidence  string
}

// connectorGroundings records each connector's level. A connector with no
// row is Documented (CA-D17: a connector stays Documented until a live run).
var connectorGroundings = []connectorGrounding{
	{ConnectorCopilotAgent, GroundingVerified, "live run 2026-10-31: list verified on a real task (grounding/live-connectors-2026-10-31.md)"},
	{ConnectorCursorCloud, GroundingVerified, "live run 2026-11-01 (docs/cloud-agents.md, Cursor Cloud Agents)"},
	{ConnectorDevin, GroundingVerified, "live run 2026-11-01 (docs/cloud-agents.md, Devin)"},
	{ConnectorQoderCloud, GroundingVerified, "live check 2026-11-02, free account, region global (docs/cloud-agents.md, Qoder Cloud Agents: list, environment and events shapes; credits from the session total)"},
	// Lane CA-V6: api.cline.bot's session API is undocumented; read from
	// npm @cline/core 0.2.0 and cline/cline a6507a62. The live run of
	// 2026-11-02 is evidence, not documentation: the level stays.
	{ConnectorClineCloud, GroundingObservedUndocumented, "@cline/core 0.2.0 type declarations and compiled client; cline/cline a6507a62 (grounding/wave-c-vendors-2026-11-01.md section 6); live run 2026-11-02 (free account, one session: list, status and history shapes confirmed with an app.cline.bot API key)"},
}

// Grounding returns the connector's grounding level.
func (c Connector) Grounding() Grounding {
	for _, r := range connectorGroundings {
		if r.connector == c.ID {
			return r.level
		}
	}
	return GroundingDocumented
}

// driftTest names the schema-drift test of one vendor surface: the Go
// package directory (relative to the repository root) and the test
// function.
type driftTest struct {
	surface vendorsurface.SurfaceID
	pkg     string
	test    string
}

// driftTests is the schema-drift test of every surface a connector at a
// level with RequiresDriftTest reads (pinned by
// TestUndocumentedConnectorsCarryDriftTests, which also checks each named
// test exists).
var driftTests = []driftTest{
	{"cline.cloud.sessions", "internal/vendorapi/cline", "TestSchemaDriftSessions"},
	{"cline.cloud.session_status", "internal/vendorapi/cline", "TestSchemaDriftSessionStatus"},
	{"cline.cloud.session_history", "internal/vendorapi/cline", "TestSchemaDriftSessionHistory"},
}

// DriftTest returns the package directory and the test function of a
// surface's schema-drift test (false when none is declared).
func DriftTest(s vendorsurface.SurfaceID) (pkg, test string, ok bool) {
	for _, d := range driftTests {
		if d.surface == s {
			return d.pkg, d.test, true
		}
	}
	return "", "", false
}

// Surfaces returns the vendor surfaces an API connector reads (list, detail
// and history drivers), sorted; nil for a CLI connector.
func (c Connector) Surfaces() []vendorsurface.SurfaceID {
	d, err := apiFor(c)
	if err != nil {
		return nil
	}
	set := map[vendorsurface.SurfaceID]bool{d.list.Surface: true}
	for _, drv := range d.detail {
		set[drv.Surface] = true
	}
	if d.history != nil {
		set[d.history.Surface] = true
	}
	out := make([]vendorsurface.SurfaceID, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
