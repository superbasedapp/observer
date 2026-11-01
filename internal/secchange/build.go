package secchange

import "time"

// FileInput is one changed file as the node's attribution sees it.
type FileInput struct {
	PathHash string
	// Added is the commit's added lines for the file (numstat).
	Added int
	// AI is the AI code lines the attribution carried into the commit;
	// Human the editor-reported human lines.
	AI    int
	Human int
}

// BuildInput is everything Build turns into a record.
type BuildInput struct {
	Binding      Binding
	Key          KeyRef
	CommittedAt  time.Time
	RecordedAt   time.Time
	Files        []FileInput
	HumanCapture string
	Sessions     []string
	Agents       []string
	Models       []string
	ToolVersions []string
	PromptIDs    []string
	Scanners     []string
	PackVersions []string
	Exceptions   []string
	Guard        Guard
	TaintAtWrite int64
	Findings     Findings
	Evidence     *Evidence
}

// Build turns attribution facts into a normalized record. The line split
// per file is a fixed rule over the commit's added lines: AI lines are
// capped at what the commit added, human lines at what is left, and the
// rest is unknown. With no human capture (anything but VS Code today) the
// human count is unmeasured, so every non-AI line is unknown, never human
// zero. A list item that does not fit the record's item shape (a model
// name with a space, for example) is left out rather than failing the
// record.
func Build(in BuildInput) Record {
	hc := HumanCaptureNone
	if in.HumanCapture == HumanCaptureVSCode {
		hc = HumanCaptureVSCode
	}
	r := Record{
		Binding:      in.Binding,
		Key:          in.Key,
		CommittedAt:  FormatTime(in.CommittedAt),
		RecordedAt:   FormatTime(in.RecordedAt),
		Lines:        Lines{HumanCapture: hc},
		Sessions:     shaped(in.Sessions),
		Agents:       shaped(in.Agents),
		Models:       shaped(in.Models),
		ToolVersions: shaped(in.ToolVersions),
		PromptIDs:    shaped(in.PromptIDs),
		Scanners:     shaped(in.Scanners),
		PackVersions: shaped(in.PackVersions),
		Exceptions:   shaped(in.Exceptions),
		Guard:        in.Guard,
		TaintAtWrite: in.TaintAtWrite,
		Findings:     in.Findings,
		Evidence:     in.Evidence,
	}
	seen := map[string]bool{}
	for _, f := range in.Files {
		if !hexRE.MatchString(f.PathHash) || seen[f.PathHash] || len(r.Files) == MaxFiles {
			continue
		}
		seen[f.PathHash] = true
		fl := splitLines(f, hc)
		r.Files = append(r.Files, fl)
		r.Lines.AI += fl.AI
		r.Lines.Human += fl.Human
		r.Lines.Unknown += fl.Unknown
	}
	return r.Normalize()
}

// splitLines is the per-file line split rule.
func splitLines(f FileInput, hc string) File {
	added := max(f.Added, 0)
	ai := min(max(f.AI, 0), added)
	human := 0
	if hc != HumanCaptureNone {
		human = min(max(f.Human, 0), added-ai)
	}
	return File{PathHash: f.PathHash, AI: int64(ai), Human: int64(human), Unknown: int64(added - ai - human)}
}

func shaped(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if itemShape(s) && len(out) < MaxListItems {
			out = append(out, s)
		}
	}
	return out
}
