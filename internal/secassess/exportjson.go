package secassess

import (
	"encoding/json"
	"fmt"
	"time"
)

// The JSON export of a checked assessment (depth plan W6b): an envelope that
// says what the file is, around the validation report and the checked model.
// The model is exactly what the page's "Copy checked model" copies today
// (Result.TM or Result.PT), after the same display redaction; it is the checked
// copy as Observer shows it, never the agent's file as written.

// ExportSchema is the schema id of the JSON envelope.
const ExportSchema = "observer.assessment-export.v1"

// exportNote is the sentence the envelope carries about what its model is.
const exportNote = "The model is the checked copy of the agent's model as Observer shows it, with recognised secrets hidden while redaction.on is true. redaction.hidden counts what hiding found while this file was made; redaction.markers counts every marker of a hidden secret the file holds, including those hidden when the copy was stored. It is not the agent's file as written."

// ExportRedaction says whether recognised secrets were hidden in the exported
// text, and in how many places. Hidden is what hiding found while the file was
// made. Markers is every marker of a hidden secret the exported text holds,
// including those hidden when the checked copy was stored: a copy redacted as
// it was stored finds nothing more now, so Hidden alone would read as "nothing
// was hidden" beside a text full of markers.
type ExportRedaction struct {
	On      bool `json:"on"`
	Hidden  int  `json:"hidden"`
	Markers int  `json:"markers"`
}

// ExportDoc is the JSON envelope of an assessment export.
type ExportDoc struct {
	// Schema is always ExportSchema.
	Schema string `json:"schema"`
	// Note says what the model is, in Observer's words.
	Note string `json:"note"`
	// RunID is the run the model belongs to; it is left out unless it is a
	// valid run id.
	RunID string `json:"run_id,omitempty"`
	// Kind is the kind id; it is left out unless the kind table knows it.
	Kind ID `json:"kind,omitempty"`
	// Contract is the result contract the model was held to.
	Contract Contract `json:"contract,omitempty"`
	// ValidatedAt is when the model was checked (UTC); a zero time is left out.
	ValidatedAt time.Time `json:"validated_at,omitzero"`
	// Anyway is true when the model was checked before the run ended.
	Anyway bool `json:"anyway"`
	// SourceSHA identifies the agent's file that was checked; it is left out
	// unless it is one to sixteen lower-case hex characters.
	SourceSHA string `json:"source_sha,omitempty"`
	// Redaction says whether recognised secrets were hidden in the exported text.
	Redaction ExportRedaction `json:"redaction"`
	// Validation is the validation report as it was stored.
	Validation Report `json:"validation"`
	// Model is the checked model: a ThreatModelDoc or a PentestDoc, by
	// Contract. It is left out when the stored copy kept only the report. It
	// decodes with json.Unmarshal into the matching type.
	Model json.RawMessage `json:"model,omitempty"`
}

// RenderExportJSON writes the JSON export: the envelope, indented by two
// spaces. HTML escaping stays on, so "<", ">" and "&" in the agent's text come
// out as <, > and & and the file can be pasted into a page
// without turning into markup. res is the checked, already redacted result.
func RenderExportJSON(m ExportMeta, res Result) ([]byte, error) {
	doc := ExportDoc{
		Schema:      ExportSchema,
		Note:        exportNote,
		Contract:    exportContract(res),
		ValidatedAt: m.ValidatedAt.UTC(),
		Anyway:      m.Anyway,
		Redaction:   ExportRedaction{On: m.RedactionOn, Hidden: m.Hidden, Markers: CountRedactionMarkers(res)},
		Validation:  res.Report,
	}
	if ValidRunID(m.RunID) {
		doc.RunID = m.RunID
	}
	if _, ok := KindByID(string(m.Kind)); ok {
		doc.Kind = m.Kind
	}
	if validExportSHA(m.SourceSHA) {
		doc.SourceSHA = m.SourceSHA
	}
	var model any
	switch {
	case res.TM != nil:
		model = res.TM
	case res.PT != nil:
		model = res.PT
	}
	if model != nil {
		raw, err := json.Marshal(model)
		if err != nil {
			return nil, fmt.Errorf("secassess.RenderExportJSON: the model: %w", err)
		}
		doc.Model = raw
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("secassess.RenderExportJSON: %w", err)
	}
	return out, nil
}
