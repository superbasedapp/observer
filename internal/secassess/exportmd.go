package secassess

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The Markdown export of a checked assessment (depth plan W6b). It is written
// by Go from the checked model and the validation report, in Observer's words;
// it is never the agent's own report.md. Where the agent's strings appear they
// sit inside fields that say so ("The agent says"), and every one of them goes
// through mdText (exportmd_escape.go). The renderer is pure: the checked, already
// display-redacted Result comes in, the document goes out.

// ExportMeta is what the renderer needs besides the checked result.
type ExportMeta struct {
	// RunID is the run the model belongs to; written only when it is a run id.
	RunID string
	// Kind is the kind id (threat_model, pentest_local, red_team_local). Its
	// title comes from the kind table, and when the table does not know it the
	// contract's plain name stands in.
	Kind ID
	// Project is the project's display name. It is a folder name, so it is
	// untrusted and escaped.
	Project string
	// ValidatedAt is when the model was checked; the zero time reads as an
	// unknown time.
	ValidatedAt time.Time
	// Anyway says the model was checked before the run ended.
	Anyway bool
	// SourceSHA identifies the agent's file that was checked (up to 16 hex
	// characters); anything else is left out.
	SourceSHA string
	// RedactionOn says recognised secrets were hidden in res before the call,
	// and Hidden how many places. The document says so, or says they were not
	// hidden.
	RedactionOn bool
	Hidden      int
	// DiagramMaxNodes and DiagramLabelChars bound the data-flow diagram of a
	// threat model; 0 reads as the defaults (MermaidOptions).
	DiagramMaxNodes   int
	DiagramLabelChars int
}

// RenderMarkdown writes the Markdown report of a checked result: the
// provenance, the reading and the validation, the model (a threat model or a
// pen test, in full: nothing is capped) and the limits that apply to it. res is
// the checked copy after display redaction; a result that kept only its
// report renders the report and says that no model was kept.
func RenderMarkdown(m ExportMeta, res Result) string {
	var w mdWriter
	contract := exportContract(res)
	w.heading(1, mdTitle(m, contract))
	mdProvenance(&w, m, CountRedactionMarkers(res))
	mdReading(&w, res)
	mdValidation(&w, res.Report)
	if res.TM != nil {
		mdThreatModel(&w, m, res)
	}
	if res.PT != nil {
		mdPenTest(&w, res)
	}
	if res.TM == nil && res.PT == nil {
		w.heading(2, "Model")
		w.para("No model was kept in this copy: the file was refused, or the model did not fit the stored copy. Only the validation report above is shown.")
	}
	mdLimits(&w, contract)
	return w.String()
}

// exportContract is the contract the document reads limits by: the report's,
// else the one the present model implies.
func exportContract(res Result) Contract {
	switch {
	case res.Report.Contract != "":
		return res.Report.Contract
	case res.TM != nil:
		return ContractThreatModel
	case res.PT != nil:
		return ContractPentest
	}
	return ""
}

// mdTitle is the heading: the kind's title (the contract's plain name when the
// kind table does not know the id) and the project's name.
func mdTitle(m ExportMeta, c Contract) string {
	title := contractPlainNames[c]
	if k, ok := KindByID(string(m.Kind)); ok {
		title = k.Title
	}
	if title == "" {
		title = contractPlainFallback
	}
	if p := mdText(m.Project); p != "" {
		return title + ": " + p
	}
	return title
}

// validExportSHA reports whether s is one to sixteen lower-case hex
// characters, which is all a file fingerprint can be.
func validExportSHA(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// mdProvenance says where the document comes from: who wrote it, from what,
// when it was checked, how the secrets were handled and what the check covered.
func mdProvenance(w *mdWriter, m ExportMeta, marked int) {
	run := "an unnamed run"
	if ValidRunID(m.RunID) {
		run = "run " + m.RunID
	}
	when := "at an unknown time"
	if !m.ValidatedAt.IsZero() {
		when = "on " + m.ValidatedAt.UTC().Format("2006-01-02 15:04:05") + " UTC"
	}
	s := "Observer wrote this report from the checked copy of " + run + " that it kept. It is not the agent's own report: " +
		"the agent's prose is not carried over, and each sentence of the agent's that appears below is marked as the agent's. " +
		"It was validated " + when + "."
	if m.Anyway {
		s += " It was validated before the run ended, so the agent may not have finished writing the model."
	}
	w.para(s)
	if validExportSHA(m.SourceSHA) {
		w.para("The file that was checked has the fingerprint " + m.SourceSHA + ".")
	}
	w.para(redactionSentence(m, marked))
	w.para(limitText("l1"))
}

// redactionRows is how the document says what hiding did, walked top down: the
// first row whose test holds gives the sentence. Two different counts are in
// play and the words keep them apart. now is what hiding found while this
// document was made; marked is every marker of a hidden secret the text holds,
// which includes what was hidden when the checked copy was stored. A copy that
// was redacted as it was stored finds nothing more now, and a document that
// said "none to hide" beside a text full of markers would read as if nothing
// had been hidden at all.
var redactionRows = []struct {
	name  string
	when  func(on bool, now, marked int) bool
	words func(now, marked int) string
}{
	{"hiding was off", func(on bool, _, _ int) bool { return !on }, func(_, _ int) string {
		return "Hiding recognised secrets was off, so the text below is as stored and secrets Observer would recognise are not hidden."
	}},
	{"hiding found secrets now", func(_ bool, now, _ int) bool { return now > 0 }, func(now, _ int) string {
		return "Secrets Observer recognises were hidden in " + counted(now, "place", "places") + " of the text below." + redactionTail
	}},
	{"hiding found nothing more", func(_ bool, _, marked int) bool { return marked > 0 }, func(_, _ int) string {
		return "Hiding recognised secrets was on, and hiding them again found nothing more to hide in the text below." + redactionTail
	}},
	{"nothing to hide", func(bool, int, int) bool { return true }, func(_, _ int) string {
		return "Hiding recognised secrets was on, and Observer found none to hide in the text below." + redactionTail
	}},
}

const redactionTail = " Only known secret shapes are recognised, so other sensitive text may remain."

// redactionSentence says what hiding recognised secrets did to the text of the
// document: the row of redactionRows that applies, then, when the text holds
// markers of hidden secrets, how many (whatever hid them, and whenever).
func redactionSentence(m ExportMeta, marked int) string {
	out := ""
	for _, r := range redactionRows {
		if r.when(m.RedactionOn, m.Hidden, marked) {
			out = r.words(m.Hidden, marked)
			break
		}
	}
	if marked > 0 {
		out += " The text below holds " + counted(marked, "marker", "markers") + " where a secret was hidden (they read REDACTED), including any hidden when the copy was stored."
	}
	return out
}

// mdReading writes what the result does and does not mean, and what the agent
// covered, when the result has something to say about either.
func mdReading(w *mdWriter, res Result) {
	reading, coverage := CleanReading(res), CoverageLine(res)
	if reading == "" && coverage == "" {
		return
	}
	w.heading(2, "Reading")
	if reading != "" {
		w.para(reading)
	}
	if coverage != "" {
		w.para(coverage)
	}
}

// mdValidation writes the validation report: the state, what was read and
// kept, how the references fared, and every issue.
func mdValidation(w *mdWriter, rep Report) {
	w.heading(2, "Validation")
	state := "State: not stated."
	if words, ok := validationStateWords[rep.State]; ok {
		state = "State: " + string(rep.State) + ". " + words
	} else if rep.State != "" {
		state = "State: " + mdText(string(rep.State)) + "."
	}
	w.para(state)
	if rep.Fatal != "" {
		w.para("The file was refused for this reason: " + mdWords(rep.Fatal) + ".")
	}
	mdCounts(w, rep.Counts)
	mdRefTally(w, rep.Refs)
	mdRefCheck(w, rep.RefCheck)
	mdIgnored(w, rep)
	mdIssues(w, rep)
}

// mdCounts writes how many items of each collection were read, kept, refused
// and left out, in the collection names' order.
func mdCounts(w *mdWriter, counts map[string]Count) {
	if len(counts) == 0 {
		return
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	rows := make([][]string, 0, len(names))
	for _, n := range names {
		c := counts[n]
		rows = append(rows, []string{mdWords(n), mdInt(c.Read), mdInt(c.Kept), mdInt(c.Refused), mdInt(c.LeftOut)})
	}
	w.para("What the check read, and what it kept:")
	w.table([]string{"Collection", "Read", "Kept", "Refused", "Left out"}, rows)
}

// mdRefTally writes the references the agent cited, by what Observer found
// when it looked at each.
func mdRefTally(w *mdWriter, t RefTally) {
	rows := []struct {
		words string
		n     int
	}{
		{refStateWord(RefFound), t.Found},
		{refStateWord(RefExists), t.Exists},
		{refStateWord(RefClaimedNotFound), t.ClaimedNotFound},
		{refStateWord(RefMissing) + " (no such file, or the line is past its end)", t.Missing},
		{refStateWord(RefInvalid) + " (the reference is malformed)", t.Invalid},
		{refStateWord(RefUnchecked), t.Unchecked},
	}
	w.para("The references the agent cited, by what Observer found when it looked at each:")
	for _, r := range rows {
		w.bullet(0, r.words+": "+mdInt(r.n))
	}
	w.blank()
}

// mdRefCheck writes the conditions the reference tally was made under: the match
// window, and how many references quoted text the redactor changed before the
// files were searched for it. A copy that predates them (or looked at no files)
// has none and writes nothing.
func mdRefCheck(w *mdWriter, rc *RefCheck) {
	if rc == nil {
		return
	}
	if rc.WindowLines == 1 {
		w.para("References count as found only when the quoted text is on the first cited line itself.")
	} else if rc.WindowLines > 1 {
		w.para("References count as found when the quoted text is on a code line within " + mdInt(rc.WindowLines) + " lines of the first cited line.")
	}
	if rc.TextHidden > 0 {
		w.para(counted(rc.TextHidden, "reference", "references") + " " + mdPlural(rc.TextHidden, "quotes", "quote") +
			" text that was changed by hiding secrets before the files were searched for it, so " + mdPlural(rc.TextHidden, "it", "they") + " could not read as found.")
	}
}

// mdIgnored writes the fields of the agent's file that are not in the schema.
func mdIgnored(w *mdWriter, rep Report) {
	if rep.Ignored <= 0 {
		return
	}
	s := counted(rep.Ignored, "field", "fields") + " of the agent's file " + mdPlural(rep.Ignored, "was", "were") +
		" not in the schema and " + mdPlural(rep.Ignored, "was", "were") + " ignored"
	if len(rep.IgnoredKeys) > 0 {
		s += " (named by the agent as: " + mdText(strings.Join(rep.IgnoredKeys, ", "))
		if rep.Ignored > len(rep.IgnoredKeys) {
			s += ", and others"
		}
		s += ")"
	}
	w.para(s + ".")
}

// mdPlural picks the singular or the plural word for a count.
func mdPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// mdIssues writes every issue the report lists and says how many more were
// found than the list keeps.
func mdIssues(w *mdWriter, rep Report) {
	w.para("Issues listed: " + mdInt(len(rep.Issues)) + ".")
	if len(rep.Issues) > 0 {
		rows := make([][]string, 0, len(rep.Issues))
		for _, is := range rep.Issues {
			rows = append(rows, []string{mdText(is.Row), mdText(is.Code), mdText(string(is.Severity)), mdText(is.Path), mdText(is.Message)})
		}
		w.table([]string{"Rule", "Code", "Severity", "Path", "Message"}, rows)
	}
	if rep.IssuesMore > 0 {
		w.para(counted(rep.IssuesMore, "more issue was", "more issues were") + " not listed.")
	}
}

// mdLimits writes the honest limits that apply to the contract, every row, in
// the plan's order.
func mdLimits(w *mdWriter, c Contract) {
	w.heading(2, "What this does not tell you")
	for _, l := range LimitsFor(c) {
		w.bullet(0, l.Text)
	}
	w.blank()
}

// mdGenerator writes what the agent's file says about who wrote it, when it
// says anything.
func mdGenerator(w *mdWriter, g Generator, promptVersion string) {
	var parts []string
	if g.Tool != "" {
		parts = append(parts, "tool "+mdText(g.Tool))
	}
	if g.Model != "" {
		parts = append(parts, "model "+mdText(g.Model))
	}
	if promptVersion != "" {
		parts = append(parts, "prompt version "+mdText(promptVersion))
	}
	if len(parts) > 0 {
		w.para("The agent's file names its generator as: " + strings.Join(parts, ", ") + ".")
	}
}

// mdAgentList writes a heading's worth of the agent's own list under a label
// that says whose it is; an empty list writes nothing. An item that is only
// blank is left out.
func mdAgentList(w *mdWriter, label string, items []string) {
	var texts []string
	for _, it := range items {
		if t := mdText(it); t != "" {
			texts = append(texts, t)
		}
	}
	if len(texts) == 0 {
		return
	}
	w.para(label)
	for _, t := range texts {
		w.bullet(0, t)
	}
	w.blank()
}

// mdLabel is a name with its id for a table cell or a line: "Name (id)", the
// one of them that is not empty, or the name alone when both read the same.
// Both are the agent's and are escaped here.
func mdLabel(id, name string) string {
	n, i := mdText(name), mdText(id)
	switch {
	case n == "":
		return i
	case i == "" || n == i:
		return n
	}
	return n + " (" + i + ")"
}

// mdRefPlace is the place a reference cites as written: the path, then the line
// or the range.
func mdRefPlace(r Ref) string {
	s := r.Path
	switch {
	case r.Line > 0 && r.EndLine > r.Line:
		s += fmt.Sprintf(":%d-%d", r.Line, r.EndLine)
	case r.Line > 0:
		s += fmt.Sprintf(":%d", r.Line)
	}
	return s
}

// mdRef writes one reference: its place, escaped, and what Observer found when
// it looked, in the state words. A reference that earned "found near the cited
// line" also says which line the quoted text is on.
func mdRef(r Ref) string {
	s := mdText(mdRefPlace(r)) + " (" + refStateWord(r.State)
	if r.State == RefFound && r.MatchLine > 0 {
		s += ", the quoted text is on line " + mdInt(r.MatchLine)
	}
	return s + ")"
}

// mdRefs writes the references of one item, separated by semicolons; an item
// that cites none says so.
func mdRefs(refs []Ref) string {
	if len(refs) == 0 {
		return "no file or line cited"
	}
	parts := make([]string, len(refs))
	for i, r := range refs {
		parts[i] = mdRef(r)
	}
	return strings.Join(parts, "; ")
}

// mdScoreOf is the score of a stored rating: the computed score when it is
// there, else the one the rating gives.
func mdScoreOf(score int, r Rating) int {
	if score > 0 {
		return score
	}
	return r.Score()
}

// mdBandOf is the band of a stored item: the computed band when it is
// there, else the one the rating gives ("" for a rating that is not valid).
func mdBandOf(b Band, r Rating) Band {
	if b != "" {
		return b
	}
	return BandOf(r)
}

// mdRating says an item's rating: the agent's two numbers, and the band
// Observer computed from them.
func mdRating(r Rating, b Band, score int) string {
	s := "likelihood " + mdInt(r.Likelihood) + ", impact " + mdInt(r.Impact) + " (the agent's ratings); "
	band := mdBandOf(b, r)
	if band == "" {
		return s + "no band, because the ratings are not both whole numbers from 1 to 5"
	}
	return s + "band " + mdText(string(band)) + ", computed by Observer from the two ratings (score " + mdInt(mdScoreOf(score, r)) + " of 25)"
}

// mdBandCounts counts items by band, highest first; items with no valid
// rating are counted apart.
func mdBandCounts(bands []Band) string {
	counts := map[Band]int{}
	for _, b := range bands {
		counts[b]++
	}
	var parts []string
	for i := len(Bands) - 1; i >= 0; i-- {
		parts = append(parts, mdInt(counts[Bands[i]])+" "+string(Bands[i]))
		delete(counts, Bands[i])
	}
	other := 0
	for _, n := range counts {
		other += n
	}
	if other > 0 {
		parts = append(parts, mdInt(other)+" with no valid rating")
	}
	return strings.Join(parts, ", ")
}

// mdBandNote is the sentence that says what a band is, said once per list.
const mdBandNote = "A band is computed by Observer from the agent's likelihood and impact ratings, each from 1 to 5. It is an ordinal heuristic, not a probability and not a CVSS score."

// mdByScore returns the indexes 0..n-1 ordered by score, highest first, then by
// id, then by position. The order is stable and deterministic.
func mdByScore(n int, score func(i int) int, id func(i int) string) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		i, j := idx[a], idx[b]
		if si, sj := score(i), score(j); si != sj {
			return si > sj
		}
		return id(i) < id(j)
	})
	return idx
}

// mdAgentSection writes the agent's own open questions and limits under one
// heading, and nothing at all when the agent wrote neither.
func mdAgentSection(w *mdWriter, heading string, questions, limits []string) {
	if len(questions)+len(limits) == 0 {
		return
	}
	w.heading(2, heading)
	mdAgentList(w, "Open questions, as the agent wrote them:", questions)
	mdAgentList(w, "Limits, as the agent wrote them:", limits)
}
