package secassess

// The vocabulary the server sends the model view (ModelVocab in the web's
// secAssessModel.ts). The page needs the words behind the ids a model carries:
// the STRIDE and LINDDUN categories with their questions, the component types
// and their DFD classes, the test categories, the AI frameworks and the bands.
// They come from the closed tables of this package, so the page never keeps a
// second copy that could drift; the JSON keys below are the TypeScript type's
// field names.

// VocabStride is one STRIDE category.
type VocabStride struct {
	ID       string `json:"id"`
	Letter   string `json:"letter"`
	Name     string `json:"name"`
	Question string `json:"question"`
}

// VocabLinddun is one LINDDUN category.
type VocabLinddun struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Question string `json:"question"`
}

// VocabComponentType is one component type and its DFD class.
type VocabComponentType struct {
	ID string `json:"id"`
	// Class is external_entity, process, data_store or data_flow.
	Class     string `json:"class"`
	HoldsLogs bool   `json:"holds_logs,omitempty"`
	Name      string `json:"name"`
}

// VocabWSTG is one penetration test category.
type VocabWSTG struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Intent is one line on what the category tests.
	Intent string `json:"intent"`
	// AppliesWhen is the grounding fact the category needs.
	AppliesWhen string `json:"applies_when"`
}

// VocabAIFramework is one AI-application framework.
type VocabAIFramework struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ModelVocabulary is the vocabulary of the model view.
type ModelVocabulary struct {
	Stride         []VocabStride        `json:"stride"`
	Linddun        []VocabLinddun       `json:"linddun"`
	ComponentTypes []VocabComponentType `json:"component_types"`
	WSTG           []VocabWSTG          `json:"wstg"`
	AIFrameworks   []VocabAIFramework   `json:"ai_frameworks"`
	// Bands lists the bands from lowest to highest.
	Bands []string `json:"bands"`
}

// ModelVocab returns the vocabulary built from the package's tables. Every
// slice is a fresh copy, so a caller that changes the result leaves the tables
// as they are.
func ModelVocab() ModelVocabulary {
	v := ModelVocabulary{
		Stride:         make([]VocabStride, 0, len(StrideCategories)),
		Linddun:        make([]VocabLinddun, 0, len(LinddunCategories)),
		ComponentTypes: make([]VocabComponentType, 0, len(ComponentTypes)),
		WSTG:           make([]VocabWSTG, 0, len(WSTGCategories)),
		AIFrameworks:   make([]VocabAIFramework, 0, len(AIFrameworks)),
		Bands:          make([]string, 0, len(Bands)),
	}
	for _, c := range StrideCategories {
		v.Stride = append(v.Stride, VocabStride{ID: c.ID, Letter: c.Letter, Name: c.Name, Question: c.Question})
	}
	for _, c := range LinddunCategories {
		v.Linddun = append(v.Linddun, VocabLinddun{ID: c.ID, Name: c.Name, Question: c.Question})
	}
	for _, t := range ComponentTypes {
		v.ComponentTypes = append(v.ComponentTypes, VocabComponentType{ID: t.ID, Class: string(t.Class), HoldsLogs: t.HoldsLogs, Name: t.Name})
	}
	for _, c := range WSTGCategories {
		v.WSTG = append(v.WSTG, VocabWSTG{ID: c.ID, Title: c.Title, Intent: c.Intent, AppliesWhen: c.AppliesWhen})
	}
	for _, f := range AIFrameworks {
		v.AIFrameworks = append(v.AIFrameworks, VocabAIFramework{ID: f.ID, Name: f.Name})
	}
	for _, b := range Bands {
		v.Bands = append(v.Bands, string(b))
	}
	return v
}
