package osvdb

// source.go is the source order of a node's OSV databases (static feed
// mirroring plan section 7): an ordered rule table, walked top down, that
// turns the node's tenancy and its [security.deps] db_source and
// db_fallback_upstream settings into the sources a refresh tries, in
// order. It decides only; the caller opens each source.

// The sources a refresh can take its exports from.
const (
	// SourceOrgMirror is the enrolled org server's mirror (a managed node;
	// it never reaches a public host).
	SourceOrgMirror = "org_mirror"
	// SourceImport is a set copied in with `observer security scan db
	// import <dir>`; no request is made.
	SourceImport = "import"
	// SourceFeed is SuperBased's signed mirror on FeedHost (the
	// security.osv_export content kind: a base and a cumulative delta per
	// ecosystem).
	SourceFeed = "feed"
	// SourceUpstream is the OSV project's bucket on UpstreamHost, with the
	// incremental record updates (DeltaRemote).
	SourceUpstream = "upstream"
)

// The db_source settings (config.SecurityDepsDBSources).
const (
	SettingAuto     = "auto"
	SettingFeed     = "feed"
	SettingUpstream = "upstream"
	SettingImport   = "import"
)

// SourceInput is what the source order reads.
type SourceInput struct {
	// Managed is a managed node.
	Managed bool
	// Setting is [security.deps] db_source ("" reads as auto).
	Setting string
	// FallbackUpstream is [security.deps] db_fallback_upstream.
	FallbackUpstream bool
}

// sourceRow is one row of the order.
type sourceRow struct {
	name  string
	match func(SourceInput) bool
	plan  []string
}

// sourceRows is the order, walked top down; the first row that matches
// decides. The row numbers in the names follow the plan's section 7 table.
var sourceRows = []sourceRow{
	{"1: a managed node takes its org mirror only", func(in SourceInput) bool { return in.Managed }, []string{SourceOrgMirror}},
	{"2: db_source = import takes the imported set only", func(in SourceInput) bool { return in.Setting == SettingImport }, []string{SourceImport}},
	{"4: db_source = upstream takes the bucket only", func(in SourceInput) bool { return in.Setting == SettingUpstream }, []string{SourceUpstream}},
	{"3: db_source = feed takes the signed mirror only", func(in SourceInput) bool { return in.Setting == SettingFeed }, []string{SourceFeed}},
	{"3+4: auto with the fallback takes the signed mirror, then the bucket", func(in SourceInput) bool { return in.FallbackUpstream }, []string{SourceFeed, SourceUpstream}},
	{"3: auto without the fallback takes the signed mirror only", func(SourceInput) bool { return true }, []string{SourceFeed}},
}

// SourcePlan returns the sources a refresh tries, in order: the first one
// that yields a usable set serves it.
func SourcePlan(in SourceInput) []string {
	for _, r := range sourceRows {
		if r.match(in) {
			return append([]string(nil), r.plan...)
		}
	}
	return nil
}

// ServingRemote is a Remote that knows which ecosystems it holds: a
// content-channel set (the signed mirror, an imported set, the org mirror)
// holds exactly the ecosystems its manifest lists. An ecosystem a source
// opened in the order does not hold is not its to answer, so it falls
// through to the next source (TakeServed). A Remote that is not one
// (the OSV bucket) is taken to hold every ecosystem.
type ServingRemote interface {
	Serves(eco string) bool
}

// TakeServed splits the ecosystems no earlier source of the order took
// into the ones this source takes and the rest, which fall through to the
// next source: a source takes the ecosystems it holds (serves; nil holds
// every one), and the LAST source of the order takes all that are left (it
// answers what it holds, and an ecosystem it does not hold fails there and
// keeps its last-known-good export). Both keep left's order.
//
// It is what keeps a set published before an ecosystem joined the store
// (every feed manifest before the GitHub Actions ecosystem) from breaking
// the ecosystems it does list: the new one alone falls through.
func TakeServed(left []string, serves func(eco string) bool, last bool) (take, rest []string) {
	for _, eco := range left {
		if serves == nil || last || serves(eco) {
			take = append(take, eco)
			continue
		}
		rest = append(rest, eco)
	}
	return take, rest
}
