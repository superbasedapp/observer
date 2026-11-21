package secassess

// STRIDE is the threat model's base framework. Names and questions are
// Observer's own words; the letters and the per-element applicability chart
// follow the published STRIDE-per-element method.

// FrameworkSTRIDE is the framework id of STRIDE in a threat's `framework`.
const FrameworkSTRIDE = "stride"

// StrideCategory is one STRIDE category.
type StrideCategory struct {
	// ID is the category id written in a threat's `category`.
	ID string
	// Letter is the single-letter form, used in a derived rule id.
	Letter string
	// Name is the plain-words name.
	Name string
	// Question is what the category asks of one element.
	Question string
}

// StrideCategories lists the six categories in the published order.
var StrideCategories = []StrideCategory{
	{"spoofing", "S", "Spoofing", "Can something pretend to be this element, or to be a caller of it?"},
	{"tampering", "T", "Tampering", "Can data or code here be changed without the owner knowing?"},
	{"repudiation", "R", "Repudiation", "Can someone do something here and later deny it, because nothing records it?"},
	{"information_disclosure", "I", "Information disclosure", "Can data reach someone who should not see it?"},
	{"denial_of_service", "D", "Denial of service", "Can someone make this element unavailable or exhaust it?"},
	{"elevation_of_privilege", "E", "Elevation of privilege", "Can someone do more here than they are allowed to?"},
}

// StrideCategoryByID returns the category with the given id.
func StrideCategoryByID(id string) (StrideCategory, bool) {
	for _, c := range StrideCategories {
		if c.ID == id {
			return c, true
		}
	}
	return StrideCategory{}, false
}

// DFDClass is the data-flow-diagram class of an element, which decides which
// STRIDE categories apply to it.
type DFDClass string

// The four DFD classes of the STRIDE-per-element chart.
const (
	ClassExternalEntity DFDClass = "external_entity"
	ClassProcess        DFDClass = "process"
	ClassDataStore      DFDClass = "data_store"
	ClassDataFlow       DFDClass = "data_flow"
)

// strideChart is the STRIDE-per-element chart: the categories that apply to
// each class. Repudiation applies to a data store only when it holds logs
// (ApplicableStride adds it).
var strideChart = map[DFDClass][]string{
	ClassExternalEntity: {"spoofing", "repudiation"},
	ClassProcess:        {"spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"},
	ClassDataStore:      {"tampering", "information_disclosure", "denial_of_service"},
	ClassDataFlow:       {"tampering", "information_disclosure", "denial_of_service"},
}

// ApplicableStride returns the STRIDE category ids that apply to an element
// of class c, in the published order. holdsLogs adds repudiation to a data
// store (a store that holds logs is where a deniable action would be
// recorded or not).
func ApplicableStride(c DFDClass, holdsLogs bool) []string {
	want := map[string]bool{}
	for _, id := range strideChart[c] {
		want[id] = true
	}
	if c == ClassDataStore && holdsLogs {
		want["repudiation"] = true
	}
	var out []string
	for _, cat := range StrideCategories {
		if want[cat.ID] {
			out = append(out, cat.ID)
		}
	}
	return out
}

// ComponentType is one row of the component type table: the id written in a
// component's `type` and the DFD class it has.
type ComponentType struct {
	ID    string
	Class DFDClass
	// HoldsLogs marks a store whose purpose is records (repudiation applies).
	HoldsLogs bool
	Name      string
}

// ComponentTypes is the closed component type table.
var ComponentTypes = []ComponentType{
	{"service", ClassProcess, false, "Service or process"},
	{"ui", ClassProcess, false, "User interface"},
	{"job", ClassProcess, false, "Background job"},
	{"gateway", ClassProcess, false, "Gateway or proxy"},
	{"datastore", ClassDataStore, false, "Data store"},
	{"log_store", ClassDataStore, true, "Log or audit store"},
	{"queue", ClassDataStore, false, "Queue or message log"},
	{"external", ClassExternalEntity, false, "External service"},
	{"other", ClassProcess, false, "Other"},
}

// ComponentTypeByID returns the component type with the given id.
func ComponentTypeByID(id string) (ComponentType, bool) {
	for _, t := range ComponentTypes {
		if t.ID == id {
			return t, true
		}
	}
	return ComponentType{}, false
}
