package secassess

import (
	"strings"
)

// The penetration test half of the Markdown export: the agent's summary and
// the bands, the target, the coverage matrix, every finding and the agent's
// own limits. A finding's basis, evidence ids and probe ids are the agent's
// claims and read as such; the export carries no request log, and it never
// says a weakness was proved.

// mdPenTest writes every section of a pen test or red team result.
func mdPenTest(w *mdWriter, res Result) {
	pt := res.PT
	mdPTSummary(w, pt)
	mdPTTarget(w, pt)
	mdPTCoverage(w, res.Report.PT)
	mdPTFindings(w, pt.Findings)
	mdPTExercise(w, pt)
	mdAgentSection(w, "The agent's own limits", nil, pt.Limits)
}

// mdPTSummary writes the agent's summary, the method it names and the findings
// counted by band.
func mdPTSummary(w *mdWriter, pt *PentestDoc) {
	w.heading(2, "Summary")
	if s := mdText(pt.Summary); s != "" {
		w.para("The agent says: " + s)
	}
	mdGenerator(w, pt.Generator, pt.PromptVersion)
	if s := mdText(pt.Method.Standard); s != "" {
		w.para("The method the agent says it followed: " + s + ".")
	}
	bands := make([]Band, len(pt.Findings))
	for i, f := range pt.Findings {
		bands[i] = mdBandOf(f.Band, f.Rating)
	}
	w.para(counted(len(pt.Findings), "finding", "findings") + " in the model, all listed below: " + mdBandCounts(bands) + ". " + mdBandNote)
}

// mdPTTarget writes what the agent says it tested and how it started it.
func mdPTTarget(w *mdWriter, pt *PentestDoc) {
	t := pt.Target
	w.heading(2, "Target")
	w.para("Everything here is the agent's account of its own target. Observer does not see the target.")
	if s := mdText(t.URL); s != "" {
		w.bullet(0, "Address, as the agent says: "+s)
	}
	if len(t.Start.Argv) > 0 {
		w.bullet(0, "Start command, as the agent says: "+mdText(strings.Join(t.Start.Argv, " ")))
	}
	if s := mdText(t.Start.Source); s != "" {
		w.bullet(0, "Where the agent found the start command: "+s)
	}
	started := "The agent says the target started: " + mdYesNo(t.Start.Started)
	if t.Start.StartupSeconds > 0 {
		started += " (after " + counted(t.Start.StartupSeconds, "second", "seconds") + ")"
	}
	w.bullet(0, started)
	if h := t.Start.Health; h.Path != "" || h.Status != 0 {
		w.bullet(0, "Health check the agent says it used: "+mdHealth(h))
	}
	if len(t.Accounts) > 0 {
		w.bullet(0, "Test accounts, by label only (no credential is kept): "+mdAccounts(t.Accounts))
	}
	w.blank()
}

// mdHealth writes the health check the agent names.
func mdHealth(h PTHealth) string {
	var parts []string
	if s := mdText(h.Path); s != "" {
		parts = append(parts, "path "+s)
	}
	if h.Status != 0 {
		parts = append(parts, "status "+mdInt(h.Status))
	}
	return strings.Join(parts, ", ")
}

// mdAccounts writes the test accounts by label and role.
func mdAccounts(as []PTAccount) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		s := mdText(a.Label)
		if r := mdText(a.Role); r != "" {
			s += " (" + r + ")"
		}
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "; ")
}

// mdTestCategory is a test category: Observer's title for an id in the WSTG
// table, with the id; otherwise the stored title and the id as written, escaped.
func mdTestCategory(id, storedTitle string) string {
	if c, ok := WSTGCategoryByID(id); ok {
		return c.Title + " (" + id + ")"
	}
	return mdLabel(id, storedTitle)
}

// mdPTCoverage writes the coverage matrix: the agent's claim for each category
// beside the word Observer reads it as.
func mdPTCoverage(w *mdWriter, cov *PTCoverage) {
	if cov == nil {
		return
	}
	w.heading(2, "Coverage matrix")
	w.para("The matrix is the agent's claim for each category, and the word beside it is how Observer reads that claim. It is not a trace of what was tested. " + coverageCounts(cov) + ".")
	if len(cov.Rows) == 0 {
		return
	}
	rows := make([][]string, 0, len(cov.Rows))
	for _, r := range cov.Rows {
		claim := "no row"
		if r.Agent != "" {
			claim = mdWords(r.Agent)
		}
		rows = append(rows, []string{mdTestCategory(r.Category, r.Title), claim, mdWords(r.Effective), mdText(r.Reason)})
	}
	w.table([]string{"Category", "The agent's claim", "Observer's reading", "Reason, as the agent says"}, rows)
}

// mdBasis says the agent's basis for a finding, as the agent's claim.
func mdBasis(b string) string {
	if words, ok := basisWords[b]; ok {
		return words
	}
	if s := mdWords(b); s != "" {
		return "the agent gives the basis as: " + s
	}
	return "the agent gives no basis"
}

// mdPTFindings writes every finding, highest score first, then by id.
func mdPTFindings(w *mdWriter, fs []PTFinding) {
	w.heading(2, "Findings")
	if len(fs) == 0 {
		w.para("No finding is listed in this copy of the model. The reading at the top says what that does and does not mean.")
		return
	}
	w.para("Every finding in the model, highest score first and then by id. The basis, the evidence ids and the probe ids are the agent's claims, and this export carries no request log.")
	order := mdByScore(len(fs), func(i int) int { return mdScoreOf(fs[i].Score, fs[i].Rating) }, func(i int) string { return fs[i].ID })
	for _, i := range order {
		mdPTFinding(w, fs[i])
	}
}

// mdPTFinding writes one finding.
func mdPTFinding(w *mdWriter, f PTFinding) {
	w.heading(3, mdItemHeading(f.ID, f.Title))
	w.bullet(0, "Category: "+mdTestCategory(f.Category, ""))
	w.bullet(0, "Rating: "+mdRating(f.Rating, f.Band, f.Score))
	if s := mdCVSS(f); s != "" {
		w.bullet(0, s)
	}
	w.bullet(0, "Basis: "+mdBasis(f.Basis))
	if s := mdText(f.Route); s != "" {
		w.bullet(0, "Route, as the agent says: "+s)
	}
	if len(f.CWE) > 0 {
		w.bullet(0, "CWE, as the agent lists them: "+mdText(strings.Join(f.CWE, ", ")))
	}
	if len(f.Where.Refs) > 0 {
		w.bullet(0, "Cited places: "+mdRefs(f.Where.Refs))
	}
	if f.Indicator != nil {
		w.bullet(0, "Probe ids of the attack and its control, as the agent names them: "+mdIndicator(*f.Indicator))
	}
	if len(f.Evidence) > 0 {
		w.bullet(0, "Evidence ids, as the agent lists them: "+mdText(strings.Join(f.Evidence, ", ")))
	}
	if f.Status != "" {
		w.bullet(0, "Status, as the agent says: "+mdWords(f.Status))
	}
	w.blank()
	if s := mdText(f.Impact); s != "" {
		w.para("The agent says, about the impact: " + s)
	}
	if s := mdText(f.Fix); s != "" {
		w.para("The agent says, about the fix: " + s)
	}
	mdPTRepro(w, f.Reproduction)
}

// mdCVSS says a finding's CVSS 4.0 line: the agent's vector, and the base score
// Observer reads from that vector now (never a stored score), with the sentence
// that says what a base score of this kind is and the sentence that says it is a
// reading apart from the band (N-16). A score of 0.0 is shown with
// "no band", the vector and the score still there. A finding with no vector
// has no line.
func mdCVSS(f PTFinding) string {
	if f.CVSS == "" {
		return ""
	}
	s := "CVSS 4.0 base vector, as the agent wrote it: " + mdText(f.CVSS) + "; "
	score, band, ok := cvssReading(f)
	if !ok {
		return s + "Observer could not score it as a CVSS 4.0 base vector, so it shows no score."
	}
	rating := "no band"
	if band != "" {
		rating = string(band)
	}
	return s + "base score " + FormatCVSSScore(score) + " (" + rating + "), computed by Observer from the vector. " + CVSSNote + " " + CVSSApart
}

// mdIndicator writes the two probe ids a finding rests on.
func mdIndicator(i PTIndicator) string {
	var parts []string
	if s := mdText(i.Attack); s != "" {
		parts = append(parts, "attack "+s)
	}
	if s := mdText(i.Control); s != "" {
		parts = append(parts, "control "+s)
	}
	return strings.Join(parts, ", ")
}

// mdRequestText reads a reproduction request (the agent's, after the check) as
// one line of text for the export: the method and the path, then the headers
// and the body when there are any, as the stored copy holds them (a header that
// carries a credential has already lost its value). The caller escapes it.
func mdRequestText(r *PTRequest) string {
	if r == nil {
		return ""
	}
	s := strings.TrimSpace(r.Method + " " + r.Path)
	var extra []string
	var headers []string
	for _, h := range r.Headers {
		if name := strings.TrimSpace(h.Name); name != "" {
			headers = append(headers, name+": "+h.Value)
		}
	}
	if len(headers) > 0 {
		extra = append(extra, "headers: "+strings.Join(headers, "; "))
	}
	if body := strings.TrimSpace(r.Body); body != "" {
		extra = append(extra, "body: "+body)
	}
	if len(extra) == 0 {
		return s
	}
	return strings.TrimSpace(s + " (" + strings.Join(extra, ", ") + ")")
}

// mdPTRepro writes the reproduction steps as the agent wrote them.
func mdPTRepro(w *mdWriter, steps []PTRepro) {
	if len(steps) == 0 {
		return
	}
	w.para("Reproduction steps, as the agent wrote them:")
	for i, st := range steps {
		s := mdText(st.Step)
		if r := mdText(mdRequestText(st.Request)); r != "" {
			s += " Request: " + r
		}
		w.bullet(0, "Step "+mdInt(i+1)+": "+s)
	}
	w.blank()
}
