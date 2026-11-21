package sandboxopenshell

// drift.go classifies the managed gateway's config read-back as a posture
// value (OpenShell build lane O4, revision 1 R-17): whether the gateway.toml
// Observer wrote for its private gateway is still what Observer wrote.
//
// This is TAMPER-EVIDENT, never tamper-proof: the config, the record and
// the daemon all run as the same local OS user, so that user (or anything
// running as them) can rewrite the file, the record and the digest
// together, and the reading then says nothing changed. What it does catch
// is a change made outside Observer's own write path (a hand edit, a tool
// that rewrites gateway.toml, a partial tamper) between two starts.
//
// The read-back is O2's: Observer writes the config only immediately before
// a start and records the digest of what it started with
// (GatewayRecord.ConfigDigest, GatewayConfigDigest). A config matching
// either the recorded start or what this install renders now (a start in
// progress writes the file before the record) is Observer's own.

// GatewayConfigRead is how reading the config file went.
type GatewayConfigRead int

// The closed GatewayConfigRead vocabulary.
const (
	// GatewayConfigReadOK: the file was read.
	GatewayConfigReadOK GatewayConfigRead = iota
	// GatewayConfigMissing: the file does not exist.
	GatewayConfigMissing
	// GatewayConfigUnreadable: the file exists but could not be read as a
	// small regular file of this user (not owned, a link, too large, an
	// I/O error).
	GatewayConfigUnreadable
)

// GatewayDriftFacts are the read-back's facts.
type GatewayDriftFacts struct {
	// Recorded: the gateway's record file exists (Observer started its
	// private gateway at least once).
	Recorded bool
	// RecordValid: the record parsed and names the gateway.
	RecordValid bool
	// Read is how reading the config went.
	Read GatewayConfigRead
	// MatchesRecord: the config is what the recorded start used.
	MatchesRecord bool
	// MatchesWanted: the config is what this install renders now.
	MatchesWanted bool
	// DatabasePresent: the private gateway's own database file exists.
	// Only the gateway process creates it, after Observer has written the
	// config and launched the unit, so it shows a gateway ran here even
	// when the config and the record are both gone. (The gateway dir alone
	// does not: an ensure makes it before a start that may fail early, and
	// the keys are written before the config.)
	DatabasePresent bool
}

// GatewayDrift is the posture value.
type GatewayDrift string

// The closed GatewayDrift vocabulary.
const (
	// GatewayDriftNone: no managed gateway was ever started here, so there
	// is nothing to compare (reported as nothing).
	GatewayDriftNone GatewayDrift = "none"
	// GatewayDriftMatch: the config is Observer's own.
	GatewayDriftMatch GatewayDrift = "match"
	// GatewayDriftChanged: the config Observer wrote was changed or removed
	// outside Observer.
	GatewayDriftChanged GatewayDrift = "changed"
	// GatewayDriftUnknown: the read-back could not say (never read as
	// clean).
	GatewayDriftUnknown GatewayDrift = "unknown"
)

// gatewayDriftRow is one row of the drift table.
type gatewayDriftRow struct {
	rule  string
	holds func(f GatewayDriftFacts) bool
	out   GatewayDrift
}

// gatewayDriftRows is the drift table, walked top-down (CLAUDE.md rule 5).
var gatewayDriftRows = []gatewayDriftRow{
	// D0: nothing recorded and no config, but the gateway's own database
	// is there: a gateway ran here and the config and record Observer wrote
	// for it were both removed outside Observer (missing, read as changed).
	{"D0", func(f GatewayDriftFacts) bool {
		return !f.Recorded && f.Read == GatewayConfigMissing && f.DatabasePresent
	}, GatewayDriftChanged},
	// D1: nothing recorded and no config: no managed gateway here.
	{"D1", func(f GatewayDriftFacts) bool { return !f.Recorded && f.Read == GatewayConfigMissing }, GatewayDriftNone},
	// D2: nothing recorded, a config that is Observer's current render (a
	// first start that never finished writes the config before the
	// record).
	{"D2", func(f GatewayDriftFacts) bool {
		return !f.Recorded && f.Read == GatewayConfigReadOK && f.MatchesWanted
	}, GatewayDriftNone},
	// D3: nothing recorded and any other config: what it started with
	// cannot be known.
	{"D3", func(f GatewayDriftFacts) bool { return !f.Recorded }, GatewayDriftUnknown},
	// D4: a record that does not parse.
	{"D4", func(f GatewayDriftFacts) bool { return !f.RecordValid }, GatewayDriftUnknown},
	// D5: a config that cannot be read.
	{"D5", func(f GatewayDriftFacts) bool { return f.Read == GatewayConfigUnreadable }, GatewayDriftUnknown},
	// D6: the config the gateway was started with is gone.
	{"D6", func(f GatewayDriftFacts) bool { return f.Read == GatewayConfigMissing }, GatewayDriftChanged},
	// D7: the config is Observer's own.
	{"D7", func(f GatewayDriftFacts) bool { return f.MatchesRecord || f.MatchesWanted }, GatewayDriftMatch},
	// D8: anything else was changed outside Observer.
	{"D8", func(GatewayDriftFacts) bool { return true }, GatewayDriftChanged},
}

// ClassifyGatewayDrift walks the drift table and returns the value and the
// rule that decided it.
func ClassifyGatewayDrift(f GatewayDriftFacts) (GatewayDrift, string) {
	for _, r := range gatewayDriftRows {
		if r.holds(f) {
			return r.out, r.rule
		}
	}
	return GatewayDriftUnknown, ""
}
