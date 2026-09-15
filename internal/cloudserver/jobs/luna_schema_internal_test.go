package jobs

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/tagtaxonomy"
)

// TestBuildLunaResultSchemaConstrainsTaxonomyTags pins that the strict
// structured-output schema constrains taxonomy_tags to exactly the canonical
// vocabulary (tagtaxonomy.Slugs()), that suggested_tags stays free-form (the
// place any off-vocabulary or free-form tag belongs instead), and that the
// schema is still valid strict JSON Schema (additionalProperties:false, every
// property declared). This is an internal (package jobs) test because it
// reaches the unexported lunaResultSchema/buildLunaResultSchema.
func TestBuildLunaResultSchemaConstrainsTaxonomyTags(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(lunaResultSchema, &schema); err != nil {
		t.Fatalf("lunaResultSchema does not parse as JSON: %v", err)
	}

	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("additionalProperties = %v, want false", schema["additionalProperties"])
	}

	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties is not an object: %+v", schema["properties"])
	}

	taxonomyTags, ok := properties["taxonomy_tags"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.taxonomy_tags missing or not an object: %+v", properties["taxonomy_tags"])
	}
	items, ok := taxonomyTags["items"].(map[string]any)
	if !ok {
		t.Fatalf("taxonomy_tags.items missing or not an object: %+v", taxonomyTags["items"])
	}
	gotEnum := toStringSlice(t, items["enum"])
	wantEnum := tagtaxonomy.Slugs()
	if !reflect.DeepEqual(gotEnum, wantEnum) {
		t.Fatalf("taxonomy_tags.items.enum = %v, want tagtaxonomy.Slugs() = %v", gotEnum, wantEnum)
	}

	suggestedTags, ok := properties["suggested_tags"].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.suggested_tags missing or not an object: %+v", properties["suggested_tags"])
	}
	suggestedItems, ok := suggestedTags["items"].(map[string]any)
	if !ok {
		t.Fatalf("suggested_tags.items missing or not an object: %+v", suggestedTags["items"])
	}
	if _, hasEnum := suggestedItems["enum"]; hasEnum {
		t.Fatalf("suggested_tags.items carries an enum %v, want free-form (no enum)", suggestedItems["enum"])
	}
	if got := suggestedItems["type"]; got != "string" {
		t.Fatalf("suggested_tags.items.type = %v, want %q", got, "string")
	}

	wantRequired := []string{
		"title", "taxonomy_tags", "suggested_tags", "description", "confidence",
		"evidence_refs", "limitations",
		"work_done", "plans_implemented", "issues_found", "failures", "next_steps",
	}
	gotRequired := toStringSlice(t, schema["required"])
	if !reflect.DeepEqual(gotRequired, wantRequired) {
		t.Fatalf("schema.required = %v, want %v", gotRequired, wantRequired)
	}

	// The five narrative lists are plain string arrays. They are generated from
	// cloudcontract.NarrativeFields, so this walks the same source rather than
	// hand-restating the names a third time.
	//
	// They must NOT carry array count keywords: strict structured output
	// refuses minItems/maxItems/uniqueItems/contains with an invalid-schema
	// 400, which would fail every job. The count bound lives in the prompt and
	// in Result.Normalize.
	for _, field := range cloudcontract.NarrativeFields {
		prop, ok := properties[field].(map[string]any)
		if !ok {
			t.Fatalf("schema.properties.%s missing or not an object: %+v", field, properties[field])
		}
		if prop["type"] != "array" {
			t.Fatalf("%s.type = %v, want array", field, prop["type"])
		}
		for _, banned := range []string{"maxItems", "minItems", "uniqueItems", "contains"} {
			if _, present := prop[banned]; present {
				t.Fatalf("%s carries %q, which strict structured output rejects", field, banned)
			}
		}
		items, ok := prop["items"].(map[string]any)
		if !ok || items["type"] != "string" {
			t.Fatalf("%s.items = %+v, want a string item", field, prop["items"])
		}
	}
	if _, hasSchemaVersion := properties["schema_version"]; hasSchemaVersion {
		t.Fatal("schema.properties carries schema_version, which is server-owned and must never be a model output")
	}
}

// toStringSlice converts a decoded JSON []any of strings into []string,
// failing the test if any element is not a string.
func toStringSlice(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("expected a JSON array, got %T: %+v", v, v)
	}
	out := make([]string, len(raw))
	for i, e := range raw {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("element %d is not a string: %+v", i, e)
		}
		out[i] = s
	}
	return out
}

// TestLunaPromptRendersClosedVocabularies is the N5 drift pin. The failure
// classes and the MCP server families used to be RESTATED in the prompt's prose
// while the node emitted them from its own tables, so a label added on one side
// left the model reading a stale list — and a label it was never shown is a
// label it cannot interpret. Both vocabularies are now rendered from
// cloudcontract, the one package both ends import, and this test fails if a
// member of either set is missing from the built prompt (or if a placeholder
// survived unrendered).
func TestLunaPromptRendersClosedVocabularies(t *testing.T) {
	prompt := buildLunaSystemPrompt()
	for _, marker := range []string{markerMCPFamilies, markerErrorClass} {
		if strings.Contains(prompt, marker) {
			t.Errorf("marker %q survived into the built prompt — the vocabulary was not rendered", marker)
		}
	}
	for _, class := range cloudcontract.ErrorClasses() {
		if !strings.Contains(prompt, class) {
			t.Errorf("failure class %q is missing from the system prompt", class)
		}
	}
	for _, family := range cloudcontract.MCPFamilyLabels() {
		if !strings.Contains(prompt, family) {
			t.Errorf("MCP family label %q is missing from the system prompt", family)
		}
	}
	// The count form the node now ships must be explained, not just the labels.
	for _, phrase := range []string{"error_class_last", "x<count>"} {
		if !strings.Contains(prompt, phrase) {
			t.Errorf("the system prompt never explains %q", phrase)
		}
	}
	// Every narrative field must carry its OWN instruction - a field named only
	// in the output schema is a field the model has to guess the meaning of,
	// which is how "What to do next" ended up rendering limitations.
	for _, field := range cloudcontract.NarrativeFields {
		if !strings.Contains(prompt, "\n- "+field+":") {
			t.Errorf("the system prompt carries no instruction for %q", field)
		}
	}
	// The purity rule ProcessLunaCompletion ENFORCES must be stated, so a
	// rejection is something the model was told about, not a surprise.
	for _, phrase := range []string{"NEVER put an evidence identifier", "Refs belong in evidence_refs"} {
		if !strings.Contains(prompt, phrase) {
			t.Errorf("the system prompt never states %q", phrase)
		}
	}
	// Determinism: the prompt hash is part of a job's provenance.
	if again := buildLunaSystemPrompt(); again != prompt {
		t.Fatal("buildLunaSystemPrompt is not deterministic")
	}
}
