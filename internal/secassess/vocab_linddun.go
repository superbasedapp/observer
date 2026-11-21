package secassess

// LINDDUN is the privacy threat framework. It applies only to a flow that
// carries personal data (a flow's `personal_data` is true). Names and
// questions are Observer's own words.

// FrameworkLINDDUN is the framework id of LINDDUN in a threat's `framework`.
const FrameworkLINDDUN = "linddun"

// LinddunCategory is one LINDDUN category.
type LinddunCategory struct {
	ID       string
	Name     string
	Question string
}

// LinddunCategories lists the seven categories in the published order.
var LinddunCategories = []LinddunCategory{
	{"linkability", "Linkability", "Can two records or actions be tied to the same person?"},
	{"identifiability", "Identifiability", "Can a person be singled out from this data?"},
	{"non_repudiation", "Non-repudiation", "Is a person unable to deny something they would want to deny?"},
	{"detectability", "Detectability", "Can someone tell that a record about a person exists?"},
	{"disclosure_of_information", "Disclosure of information", "Can personal data reach someone who should not have it?"},
	{"unawareness", "Unawareness", "Is the person unaware of what is collected or why?"},
	{"non_compliance", "Non-compliance", "Does the handling miss a rule, policy or consent it should follow?"},
}

// LinddunCategoryByID returns the category with the given id.
func LinddunCategoryByID(id string) (LinddunCategory, bool) {
	for _, c := range LinddunCategories {
		if c.ID == id {
			return c, true
		}
	}
	return LinddunCategory{}, false
}
