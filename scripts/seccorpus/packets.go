package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// Excerpt bounds: lines around the finding, and bytes per line.
const (
	excerptBefore = 14
	excerptAfter  = 10
	excerptLine   = 240
)

// Rubric is the labelling instruction every packet carries. It is the
// method of record (docs/code-rules-precision.md quotes it).
const Rubric = `You are a security reviewer labelling the results of one static-analysis rule pack.
For each item decide one verdict, judging only the code shown (you may read more of the file at the
path given if the excerpt is not enough), and pick one reason code from the table:

  true_positive  - input_reaches_sink:      a value a caller or another party can influence reaches the
                                            dangerous call as the rule describes.
                 - unsafe_by_construction:  the code is unsafe as written whatever the input (a broken
                                            cipher, a trust-all certificate check, a password hashed with MD5).
                 - unsafe_setting:          a setting the rule names is switched to its unsafe value in code
                                            that runs (not a test of the setting).
  false_positive - constant_or_internal:    the value is a constant, or comes only from the program itself
                                            or a trusted operator, so no outside party controls it.
                 - sanitized_or_allowlisted: the value is checked, escaped, parameterised or allow-listed
                                            before it is used.
                 - not_the_weakness:        the code matches the shape but the weakness does not apply (for
                                            example MD5 used for a cache key, a random value that is not secret).
                 - wrong_match:             the rule matched something else entirely.
                 - deliberate_test_or_demo: a test, fixture or example that exercises the weakness on purpose
                                            (for example a test asserting the check rejects it).

A real but minor instance is still true_positive. When unsure, choose the verdict a careful reviewer
would defend to the developer who has to change the code. Label each item on its own; do not look
for other reviewers' labels.`

// packetItem is one finding in a packet.
type packetItem struct {
	ID      string `json:"id"`
	Rule    string `json:"rule"`
	Repo    string `json:"repo"`
	Commit  string `json:"commit"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	File    string `json:"file"`
	Excerpt string `json:"excerpt"`
}

// packet is one batch file.
type packet struct {
	Rubric string            `json:"rubric"`
	Rules  map[string]string `json:"rules"`
	Items  []packetItem      `json:"items"`
}

// indexRow maps a packet id back to its finding (packets/index.jsonl).
type indexRow struct {
	ID string `json:"id"`
	seccorpus.Finding
}

// excerpt reads lines around line from path, bounded, with line numbers;
// the reported line is marked with ">>".
func excerpt(path string, line int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var b strings.Builder
	for n := 1; sc.Scan(); n++ {
		if n < line-excerptBefore {
			continue
		}
		if n > line+excerptAfter {
			break
		}
		t := strings.ToValidUTF8(sc.Text(), "?")
		if len(t) > excerptLine {
			t = t[:excerptLine] + " [cut]"
		}
		mark := "  "
		if n == line {
			mark = ">>"
		}
		fmt.Fprintf(&b, "%s%5d| %s\n", mark, n, t)
	}
	return b.String(), sc.Err()
}

// writePackets writes the reviewer packets for every candidate into out,
// which must lie outside this checkout (packets carry source text).
// It labels every result of each rule in full (P-077: a rule proposed for
// blocking) and caps the others at capPerRule; the selection and the full
// list are recorded in corpus/labelset.jsonl, and the batch manifest's
// skeleton in corpus/batches.tsv.
func writePackets(p paths, dest, out string, batch int, seed uint64, capPerRule int, full []string) error {
	if dest == "" || out == "" || batch < 1 || capPerRule < 1 {
		return fmt.Errorf("packets: -dest, -out, a positive -batch and a positive -cap are required (label a rule in full with -full)")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if ok, err := outside(out, root); err != nil || !ok {
		return fmt.Errorf("packets: %s must lie outside this checkout", out)
	}
	all, err := readJSONL[seccorpus.Finding](p.file("candidates.jsonl"))
	if err != nil {
		return err
	}
	pack, err := secrulepack.Floor()
	if err != nil {
		return err
	}
	for _, r := range full {
		if _, ok := pack.Rule(r); !ok {
			return fmt.Errorf("packets: -full names %s, which is not a rule of the pack", r)
		}
	}
	cands := seccorpus.SelectForLabelling(all, seed, capPerRule, full)
	if err := writeLabelset(p.file("labelset.jsonl"), labelsetHeader{Cap: capPerRule, LabelSeed: seed, Full: full}, cands); err != nil {
		return err
	}
	files := pack.Files()
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	byURL := map[string]repo{}
	repos, err := readRepos(p.file("repos.tsv"))
	if err != nil {
		return err
	}
	for _, r := range repos {
		byURL[r.URL] = r
	}
	var index []indexRow
	var batches [][]string
	for start, n := 0, 0; start < len(cands); start, n = start+batch, n+1 {
		end := min(start+batch, len(cands))
		pk := packet{Rubric: Rubric, Rules: map[string]string{}}
		for i, f := range cands[start:end] {
			r, ok := pack.Rule(f.Rule)
			if !ok {
				return fmt.Errorf("packets: rule %s is not in the pack", f.Rule)
			}
			pk.Rules[f.Rule] = string(files[r.File])
			clone := filepath.Join(dest, byURL[f.Repo].dir())
			full := filepath.Join(clone, filepath.FromSlash(f.Path))
			ex, err := excerpt(full, f.Line)
			if err != nil {
				ex = "(the file could not be read: " + err.Error() + ")"
			}
			id := fmt.Sprintf("p%05d", start+i+1)
			pk.Items = append(pk.Items, packetItem{ID: id, Rule: f.Rule, Repo: f.Repo, Commit: f.Commit, Path: f.Path, Line: f.Line, File: full, Excerpt: ex})
			index = append(index, indexRow{ID: id, Finding: f})
		}
		ids := make([]string, 0, len(pk.Items))
		for _, it := range pk.Items {
			ids = append(ids, it.ID)
		}
		batches = append(batches, ids)
		if err := writeJSON(filepath.Join(out, batchName(n+1)+".json"), pk); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, batchName(n+1)+".txt"), []byte(renderPacket(pk)), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("%d findings in %d packets under %s\n", len(cands), len(batches), out)
	if err := writeBatchesSkeleton(p, batches); err != nil {
		return err
	}
	return writeJSONL(filepath.Join(out, "index.jsonl"), index)
}

// renderPacket is a packet as plain text (the same content as its JSON,
// one excerpt line per line), for a reviewer whose reader cuts long lines.
func renderPacket(pk packet) string {
	var b strings.Builder
	b.WriteString("RUBRIC\n\n" + pk.Rubric + "\n\nRULES\n")
	ids := make([]string, 0, len(pk.Rules))
	for id := range pk.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "\n--- rule %s ---\n%s\n", id, pk.Rules[id])
	}
	b.WriteString("\nITEMS\n")
	for _, it := range pk.Items {
		fmt.Fprintf(&b, "\n=== %s  rule %s\n    %s @ %s\n    %s line %d\n    file: %s\n%s", it.ID, it.Rule, it.Repo, it.Commit, it.Path, it.Line, it.File, it.Excerpt)
	}
	return b.String()
}
