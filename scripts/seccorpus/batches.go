package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/seccorpus"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// labelsetSchema names the header line of corpus/labelset.jsonl.
const labelsetSchema = "sbo-labelset-v1"

// labelsetHeader is the first line of corpus/labelset.jsonl: how the
// findings to label were selected. Full lists the rules labelled in full
// whatever their count (a rule proposed for blocking, P-077); every other
// rule kept the cap. A labelset with no header (lane SEC-G3's) reads as
// having no rule in full.
type labelsetHeader struct {
	Labelset  string   `json:"labelset"`
	Cap       int      `json:"cap"`
	LabelSeed uint64   `json:"label_seed"`
	Full      []string `json:"full"`
}

// writeLabelset writes the header line and then one finding per line.
func writeLabelset(path string, h labelsetHeader, cands []seccorpus.Finding) error {
	h.Labelset = labelsetSchema
	h.Full = append([]string{}, h.Full...)
	sort.Strings(h.Full)
	head, err := marshalJSONL([]labelsetHeader{h})
	if err != nil {
		return err
	}
	rows, err := marshalJSONL(cands)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(head, rows...), 0o644)
}

// readLabelset reads corpus/labelset.jsonl: its header (zero when the file
// has none, as lane SEC-G3's) and its findings.
func readLabelset(path string) (labelsetHeader, []seccorpus.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return labelsetHeader{}, nil, err
	}
	var h labelsetHeader
	offset := 0
	if first, rest, _ := bytes.Cut(b, []byte("\n")); bytes.Contains(first, []byte(`"labelset"`)) {
		hs, err := parseJSONL[labelsetHeader](path, first, 0)
		if err != nil || len(hs) != 1 || hs[0].Labelset != labelsetSchema {
			return labelsetHeader{}, nil, fmt.Errorf("%s: the first line is not a %s header", path, labelsetSchema)
		}
		h, b, offset = hs[0], rest, 1
	}
	cands, err := parseJSONL[seccorpus.Finding](path, b, offset)
	return h, cands, err
}

// labellersFile is the committed list of every reviewer id that ever
// labelled this corpus, one per line with the lane that ran it. record
// refuses each of them as the spot-checker (ruling P-064).
const labellersFile = "labellers.tsv"

// readLabellers reads corpus/labellers.tsv: id<TAB>lane, # comments. An
// empty or unreadable list is an error, never "no labellers".
func readLabellers(p paths) ([]string, error) {
	path := p.file(labellersFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		id := f[0]
		if len(f) != 2 || f[1] == "" || !strings.HasPrefix(id, secrulepack.SpotcheckerAgentPrefix) || !secrulepack.ValidSpotchecker(id) {
			return nil, fmt.Errorf("%s:%d: want agent:<id><TAB>lane", path, i+1)
		}
		if seen[strings.ToLower(id)] {
			return nil, fmt.Errorf("%s:%d: %s is listed twice", path, i+1, id)
		}
		seen[strings.ToLower(id)] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no labeller", path)
	}
	return out, nil
}

// batchesFile is the content-free batch manifest of the current
// measurement: which reviewer, run as which agent, labelled which packet
// batch (lane SEC-G3 audit finding 6: independence shown, not only
// claimed). It holds no excerpt and no finding, only counts and a digest
// of the batch's packet ids.
const batchesFile = "batches.tsv"

// batchesHeader is the manifest's column line. isolation is set by the
// labelling harness, never by a labeller or by hand: "attested" when the
// harness can attest that the run labelled its batch isolated from the
// other side's labels, unset ("-") otherwise. No harness attests isolation
// yet, so every row is "-" (lane SEC-G4 audit finding 1).
const batchesHeader = "batch\tside\treviewer\trun_agent\tpackets\tids_sha256\tisolation"

// batchesHeaderV1 is the column line before the isolation column (lane
// SEC-G4's own manifest as the lane committed it); it reads as unset.
const batchesHeaderV1 = "batch\tside\treviewer\trun_agent\tpackets\tids_sha256"

// attestedIsolated is the isolation value only the harness writes.
const attestedIsolated = "attested"

// unset is a manifest cell the packets step leaves for the person who runs
// the reviewers to fill.
const unset = "-"

// batchRow is one manifest row: one side's labelling of one packet batch.
type batchRow struct {
	Batch    string
	Side     string
	Reviewer string
	RunAgent string
	Packets  int
	IDsSHA   string
	// Isolation is attestedIsolated or unset ("-").
	Isolation string
}

// idsDigest is the sha256 of a batch's packet id list, one id per line.
func idsDigest(ids []string) string {
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

// batchName is a packet batch's name (and its files' base name).
func batchName(n int) string { return fmt.Sprintf("batch-%03d", n) }

// readBatches reads corpus/batches.tsv (# comments, then the column line,
// then rows). A missing file reads as no rows.
func readBatches(p paths) ([]batchRow, error) {
	path := p.file(batchesFile)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []batchRow
	header, cols := false, 0
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !header {
			switch l {
			case batchesHeader:
				cols = 7
			case batchesHeaderV1:
				cols = 6
			default:
				return nil, fmt.Errorf("%s:%d: want the column line %q", path, i+1, batchesHeader)
			}
			header = true
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != cols {
			return nil, fmt.Errorf("%s:%d: want %d columns", path, i+1, cols)
		}
		isolation := unset
		if cols == 7 {
			isolation = f[6]
		}
		if isolation != unset && isolation != attestedIsolated {
			return nil, fmt.Errorf("%s:%d: isolation %q (want %s, set by the harness, or %s)", path, i+1, isolation, attestedIsolated, unset)
		}
		n, err := strconv.Atoi(f[4])
		if err != nil || n < 1 {
			return nil, fmt.Errorf("%s:%d: packets %q", path, i+1, f[4])
		}
		if f[1] != seccorpus.ReviewerA && f[1] != seccorpus.ReviewerB {
			return nil, fmt.Errorf("%s:%d: side %q (want a or b)", path, i+1, f[1])
		}
		if len(f[5]) != 64 {
			return nil, fmt.Errorf("%s:%d: ids_sha256 %q", path, i+1, f[5])
		}
		out = append(out, batchRow{Batch: f[0], Side: f[1], Reviewer: f[2], RunAgent: f[3], Packets: n, IDsSHA: f[5], Isolation: isolation})
	}
	return out, nil
}

// secondPassAttested reports whether the manifest marks the second pass
// attested isolated: it lists second-pass (side b) rows and every one of
// them is attestedIsolated. Nothing writes that value yet, so it is false
// for every manifest today.
func secondPassAttested(rows []batchRow) bool {
	n := 0
	for _, r := range rows {
		if r.Side != seccorpus.ReviewerB {
			continue
		}
		if r.Isolation != attestedIsolated {
			return false
		}
		n++
	}
	return n > 0
}

// writeBatchesSkeleton writes the manifest's skeleton for a fresh set of
// packets: one row per batch per side, with the reviewer and run agent
// unset ("-") for whoever runs the reviewers to fill.
func writeBatchesSkeleton(p paths, batches [][]string) error {
	var b strings.Builder
	b.WriteString("# The labelling batch manifest (content free: no excerpt, no finding). One row per packet batch per\n")
	b.WriteString("# side: the reviewer id (listed in labellers.tsv), the id of the fresh agent run that labelled the\n")
	b.WriteString("# batch (one agent per batch per side, never shared), the batch's packet count and the sha256 of its\n")
	b.WriteString("# packet id list (one id per line). `seccorpus labels` refuses a label file whose batch is not here.\n")
	b.WriteString("# isolation is the labelling harness's to set (attested), never a labeller's; no harness attests it yet, so it\n")
	b.WriteString("# stays -, and a measurement whose passes agree on every verdict and reason code is one effective pass.\n")
	b.WriteString(batchesHeader + "\n")
	for i, ids := range batches {
		for _, side := range []string{seccorpus.ReviewerA, seccorpus.ReviewerB} {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", batchName(i+1), side, unset, unset, len(ids), idsDigest(ids), unset)
		}
	}
	return os.WriteFile(p.file(batchesFile), []byte(b.String()), 0o644)
}

// checkBatches checks the manifest's rows as a whole: each batch and side
// once, a filled reviewer that labellers.tsv lists and that is one id per
// side (never the same on both sides), and a filled run agent of the form
// agent:<id> that is no labeller's id and runs one batch on one side only.
func checkBatches(rows []batchRow, labellers []string) error {
	isLabeller := map[string]bool{}
	for _, l := range labellers {
		isLabeller[strings.ToLower(l)] = true
	}
	seen, agents, sideReviewer := map[string]bool{}, map[string]string{}, map[string]string{}
	for _, r := range rows {
		k := r.Batch + "/" + r.Side
		switch {
		case seen[k]:
			return fmt.Errorf("batches: %s side %s is listed twice", r.Batch, r.Side)
		case prepared(r):
			// A batch prepared for a labelling run still to come (lane
			// SEC-G5: the side-b batches await their attested relabel);
			// importLabels refuses labels for it.
			seen[k] = true
			continue
		case r.Reviewer == unset || r.RunAgent == unset:
			return fmt.Errorf("batches: %s side %s has no reviewer or run agent filled in", r.Batch, r.Side)
		case !isLabeller[strings.ToLower(r.Reviewer)]:
			return fmt.Errorf("batches: %s side %s: reviewer %s is not in %s", r.Batch, r.Side, r.Reviewer, labellersFile)
		case !strings.HasPrefix(r.RunAgent, secrulepack.SpotcheckerAgentPrefix) || !secrulepack.ValidSpotchecker(r.RunAgent) || isLabeller[strings.ToLower(r.RunAgent)]:
			return fmt.Errorf("batches: %s side %s: run agent %q (want agent:<id> of the run itself)", r.Batch, r.Side, r.RunAgent)
		}
		seen[k] = true
		if prev, ok := agents[strings.ToLower(r.RunAgent)]; ok {
			return fmt.Errorf("batches: run agent %s labelled both %s and %s (one fresh agent per batch per side)", r.RunAgent, prev, k)
		}
		agents[strings.ToLower(r.RunAgent)] = k
		if prev, ok := sideReviewer[r.Side]; ok && !strings.EqualFold(prev, r.Reviewer) {
			return fmt.Errorf("batches: side %s names two reviewers, %s and %s", r.Side, prev, r.Reviewer)
		}
		sideReviewer[r.Side] = r.Reviewer
	}
	if a, b := sideReviewer[seccorpus.ReviewerA], sideReviewer[seccorpus.ReviewerB]; a != "" && strings.EqualFold(a, b) {
		return fmt.Errorf("batches: both sides name the reviewer %s", a)
	}
	return nil
}

// prepared reports a manifest row whose reviewer and run agent are both
// still unset: the batch is prepared for a labelling run still to come.
func prepared(r batchRow) bool { return r.Reviewer == unset && r.RunAgent == unset }

// packetIDs reads one packet batch's ids from the packets directory.
func packetIDs(pk, batch string) ([]string, error) {
	var pkt packet
	if err := readJSON(filepath.Join(pk, batch+".json"), &pkt); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(pkt.Items))
	for _, it := range pkt.Items {
		ids = append(ids, it.ID)
	}
	return ids, nil
}

// packetBatches lists the batch names of a packets directory.
func packetBatches(pk string) ([]string, error) {
	m, err := filepath.Glob(filepath.Join(pk, "batch-*.json"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range m {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Strings(out)
	return out, nil
}
