package genaiattr

import (
	"reflect"
	"testing"
)

// TestPromptStampKeys pins the prompt registry's span stamp (contract
// docs/plans/plane-a-sdk-buildout/contracts/prompts.md section 5, lane B8):
// the SDKs emit sbo.prompt.*, the Langfuse spellings follow.
func TestPromptStampKeys(t *testing.T) {
	for f, want := range map[Field][]string{
		FieldPromptName:    {"sbo.prompt.name", "langfuse.observation.prompt.name"},
		FieldPromptVersion: {"sbo.prompt.version", "langfuse.observation.prompt.version"},
		FieldPromptLabel:   {"sbo.prompt.label"},
		FieldPromptCohort:  {"sbo.prompt.cohort"},
	} {
		if got := Keys(f); !reflect.DeepEqual(got, want) {
			t.Errorf("Keys(%s) = %v, want %v", f, got, want)
		}
	}
}
