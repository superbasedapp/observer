package store

// MaxCodeIntelImportSites caps the sites CodeIntelProjectImports returns.
const MaxCodeIntelImportSites = 200000

// CodeIntelImportSite is one IMPORTS site of a project's codeintel index:
// the importing file's stored path and the import specifier as written.
type CodeIntelImportSite struct {
	File string
	Spec string
}

// CodeIntelImports is a project's IMPORTS sites for one language and how
// much of the language's file set the index holds (Files rows, Indexed of
// them with status 'indexed'). The types live in this untagged file so a
// build without the codeintel component (codeintel_omit.go) still names
// them.
type CodeIntelImports struct {
	Sites     []CodeIntelImportSite
	Files     int
	Indexed   int
	Truncated bool
}

// Caps of CodeIntelProjectCalls.
const (
	// MaxCodeIntelCallSites caps the call sites returned.
	MaxCodeIntelCallSites = 50000
	// MaxCodeIntelCallNames caps the callee names asked for.
	MaxCodeIntelCallNames = 256
)

// CodeIntelCallSite is one CALLS site of a project's codeintel index: the
// file's stored path, the callee name and the bounded call excerpt the
// index keeps (codeintel_sites.raw_text, from the call's start).
type CodeIntelCallSite struct {
	File string
	Name string
	Text string
}

// CodeIntelCalls is a project's CALLS sites for some callee names.
type CodeIntelCalls struct {
	Sites     []CodeIntelCallSite
	Truncated bool
}
