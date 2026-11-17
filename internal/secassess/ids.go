package secassess

// Item ids and the caps the validator holds a model to. Every cap is a named
// constant so a test can build the file that sits exactly on it and the file
// one past it.

// MaxModelBytes is the default size cap of an assessment.json (validator row
// V1). The setting model_max_mib moves it between 1 MiB and
// MaxModelBytesCeiling; with it, the size is the only thing that bounds how many
// threats, findings and mitigations a model may hold.
const MaxModelBytes = 4 << 20

// MaxModelBytesCeiling is the largest size cap the setting allows. The stored
// copy of a checked model (secassesssvc side data) is sized from it.
const MaxModelBytesCeiling = 32 << 20

// MaxModelDepth is the JSON nesting cap of an assessment.json (V1).
const MaxModelDepth = 32

// Collection caps (V3). An item past a cap is not read, and the validation
// report counts the items left out. These are structural bounds on the shape of
// a model, each with a reason in plan section 12.4; the findings themselves
// (threats, no-threat rows, penetration test findings, and the mitigations of a
// threat) are not capped by count, only by the model's byte cap.
const (
	maxComponents    = 200
	maxZones         = 50
	maxActors        = 50
	maxAssets        = 200
	maxEntryPoints   = 200
	maxFlows         = 400
	maxAttackTrees   = 20
	maxTreeNodes     = 100
	maxTreeDepth     = 20
	maxScopePaths    = 50
	maxAssumptions   = 20
	maxOpenQuestions = 20
	maxLimits        = 20
	maxPerItemList   = 8  // refs, steps, evidence per item
	maxSmallList     = 5  // probe ids, cwe, capec, asvs per item
	maxTechList      = 10 // tech, data classes, stored_in, data, crosses per item
	maxCoverageRows  = 60
	maxArgv          = 20
	maxAccounts      = 10
	maxRefSpan       = 200 // lines in one reference range
	maxIssues        = 200 // issues one validation report lists
	maxChainSteps    = 40  // steps in a red team exercise's chain (V16)
)

// Text caps in runes (V6).
const (
	capSummary     = 1200
	capDescription = 600
	capShort       = 200 // mitigation text, reasons, notes
	capImpact      = 400 // impact and fix
	capTitle       = 120
	capName        = 80
	capNeedle      = 120
	capPath        = 300
	capProtocol    = 40
	capRoute       = 200
	capRequestPath = 512 // a reproduction request's path and query
	capRequestBody = 2048
	capHeaderValue = 256
	capMatchText   = 80 // one text of an indicator's condition
	capArgvItem    = 200
	minNeedleRunes = 8
)

// ValidItemID reports whether s is an id the validator accepts for an item:
// an ASCII letter or digit, then up to 47 letters, digits, dots, underscores
// and hyphens. Item ids appear in references between items and in imported
// finding text, so the alphabet is closed.
func ValidItemID(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
