//go:build !sbo_omit_security

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_check.go is `observer security assess check <file>`: the
// self-check a threat model, penetration test, red team or retest run is told
// about in its task (secassess.SelfCheckCommand). It reads the agent's
// assessment.json through the confined reader, runs the validator's structure
// rows (and, for a threat model or penetration test, its reference rows)
// against the working directory and prints which items would be refused or left
// out and why, so the agent can fix its file before it finishes instead of the
// developer finding out afterwards. It opens neither the node database nor the
// configuration, makes no network call and writes nothing; the dashboard's
// Validate button is the same check with the developer's own settings and a
// stored copy.
//
// The file's own schema word picks the contract (secassess.ContractOfSchema, the
// one table every schema the tasks ask for is a row of), and the contract picks
// the rows the check reports and what it adds to the validator's options
// (securityAssessChecks). A red team writes the penetration test's schema, so
// it is read as one.
//
// It checks structure and file references only. It says so, and it never says
// the agent's reasoning is right.

// securityAssessCheck is what the self-check does for one contract: the
// validator rows it reports, and what it adds to the options beyond the
// defaults (nil: nothing).
type securityAssessCheck struct {
	rows []string
	// refs says the contract has file references, so the report counts them.
	refs    bool
	prepare func(projectAbs, runID string, data []byte, o *secassess.ValidateOptions) (note string)
}

// securityAssessChecks is the table of the self-check, by contract. The rows are
// the structure and the references. For a threat model or penetration test: scope
// (V9) needs the plan, the band (V10) is a computed value, and the coverage rows
// (V11 to V13) depend on the settings the developer chose, so none of those is
// the agent's to fix from here. For a retest: its own rows (RT3 to RT6), which
// hold the file to the findings the retest replayed (so the check needs the list
// the run folder holds, prepareRetestCheck) and say which of them have no result.
// A contract with no row here is not checked (the command refuses it).
var securityAssessChecks = map[secassess.Contract]securityAssessCheck{
	secassess.ContractThreatModel: {rows: []string{"V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"}, refs: true},
	secassess.ContractPentest:     {rows: []string{"V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"}, refs: true},
	secassess.ContractRetest:      {rows: []string{"V1", "V2", "RT3", "RT4", "RT5", "RT6"}, prepare: prepareRetestCheck},
}

// securityAssessCheckRow reports whether a contract's check reports a row.
func securityAssessCheckRow(c secassess.Contract, row string) bool {
	return slices.Contains(securityAssessChecks[c].rows, row)
}

// securityAssessSchemaWords lists the schema ids the check reads: "a, b or c".
func securityAssessSchemaWords() string {
	var ids []string
	for _, m := range secassess.ModelContracts {
		if _, ok := securityAssessChecks[m.Contract]; ok {
			ids = append(ids, m.Schema)
		}
	}
	if len(ids) < 2 {
		return strings.Join(ids, "")
	}
	return strings.Join(ids[:len(ids)-1], ", ") + " or " + ids[len(ids)-1]
}

// prepareRetestCheck gives a retest's check what the dashboard's own check holds
// the file to: the findings the retest replayed. The dashboard rebuilds them from
// the earlier run's stored model; this command opens no database, so it reads
// the ids from the request helper's settings in the run folder (probe.json,
// "replay": Observer wrote it from that same model when the retest started). A
// folder that holds none leaves only the file's own findings to check against,
// and the note says the list could not be checked.
func prepareRetestCheck(projectAbs, runID string, data []byte, o *secassess.ValidateOptions) string {
	ids := secassesssvc.ReplayedFindings(projectAbs, runID)
	note := ""
	if len(ids) == 0 {
		// The file's own findings: nothing it names can be called unknown.
		var doc struct {
			Results []struct {
				Finding string `json:"finding"`
			} `json:"results"`
		}
		_ = json.Unmarshal(data, &doc)
		for _, r := range doc.Results {
			if secassess.ValidItemID(r.Finding) && !slices.Contains(ids, r.Finding) {
				ids = append(ids, r.Finding)
			}
		}
		note = "The run folder holds no list of the findings this retest replayed, so this check cannot say whether each result names one of them or whether one was left out; the dashboard's check can."
	}
	b := &secassess.RetestBasis{Findings: make([]secassess.RetestFinding, len(ids))}
	for i, id := range ids {
		b.Findings[i] = secassess.RetestFinding{ID: id}
	}
	o.Retest = b
	return note
}

// securityAssessCheckMaxLines bounds the issue lines printed.
const securityAssessCheckMaxLines = 40

// errSecurityAssessCheck is the error a check that found something returns, so
// the command's exit status says so. The report itself is on the output.
var errSecurityAssessCheck = errors.New("the assessment would not be accepted as written")

// securityAssessSubcommands are the `observer security assess` verbs.
func securityAssessSubcommands() []*cobra.Command {
	assess := &cobra.Command{
		Use:   "assess",
		Short: "Agent-run security assessments: check a result file",
		Long: "The verbs of the agent-run security assessments (the Code security page).\n" +
			"`check` is the self-check a threat model, penetration test, red team or retest agent is told to run on its own assessment.json.",
	}
	assess.AddCommand(newSecurityAssessCheckCmd())
	return []*cobra.Command{assess}
}

func newSecurityAssessCheckCmd() *cobra.Command {
	var project, runID string
	var asJSON bool
	c := &cobra.Command{
		Use:   "check <assessment.json>",
		Short: "Check an assessment.json: which items would be refused or left out, and why",
		Long: "Reads an assessment.json written for a threat model, penetration test, red team or retest run.\n" +
			"For a threat model, penetration test or red team it checks the structure and the file references\n" +
			"against the project: the schema and the run id, the sizes, the ids and the closed words, the\n" +
			"references between items and whether each cited file and line exists. For a retest it checks that\n" +
			"each result names one of the findings the retest replayed (the list in the run folder), once, with\n" +
			"a label from the closed list. It prints which items would be refused or left out and why, and the\n" +
			"reference counts. Exit status 0 means nothing would be refused or left out.\n\n" +
			"It checks structure and file references only. It does not check that the reasoning is right.\n" +
			"It opens no database and no configuration, makes no network call and writes nothing, so it uses\n" +
			"the default settings (a reference reads found within 5 lines of the cited line); the file\n" +
			"must be inside the project (the current directory, or --project); a relative path is relative to it.",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecurityAssessCheck(cmd.OutOrStdout(), project, args[0], runID, asJSON)
		},
	}
	c.Flags().StringVar(&project, "project", ".", "the project folder the file's references are checked against")
	c.Flags().StringVar(&runID, "run", "", "the run id the file must name (default: the file's folder name, or the id inside the file)")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return c
}

// securityAssessCheckJS is the --json output.
type securityAssessCheckJS struct {
	File   string                `json:"file"`
	Schema string                `json:"schema,omitempty"`
	Run    string                `json:"run,omitempty"`
	State  string                `json:"state"`
	Fatal  string                `json:"fatal,omitempty"`
	Issues []secassess.Issue     `json:"issues,omitempty"`
	More   int                   `json:"issues_more,omitempty"`
	Refs   secassess.RefTally    `json:"refs"`
	Counts map[string]countsJSON `json:"counts,omitempty"`
	Note   string                `json:"note,omitempty"`
}

type countsJSON struct {
	Read    int `json:"read"`
	Refused int `json:"refused,omitempty"`
	LeftOut int `json:"left_out,omitempty"`
	Kept    int `json:"kept"`
}

// securityAssessCheckInput names the file and finds what the validator needs
// from it: the contract (from its schema word) and the run id.
func securityAssessCheckInput(projectAbs, path, runFlag string) (rel string, data []byte, contract secassess.Contract, runID string, err error) {
	// A relative path is relative to the project folder.
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(projectAbs, path)
	}
	r, err := filepath.Rel(projectAbs, abs)
	if err != nil || r == "." || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", nil, "", "", fmt.Errorf("the file %s is not inside the project %s", path, projectAbs)
	}
	rel = filepath.ToSlash(r)
	data, err = secassesssvc.ReadResult(projectAbs, rel, secassess.MaxModelBytesCeiling)
	switch {
	case errors.Is(err, secassesssvc.ErrAbsent):
		return rel, nil, "", "", fmt.Errorf("there is no file at %s", rel)
	case errors.Is(err, secassesssvc.ErrNotRegular):
		return rel, nil, "", "", fmt.Errorf("%s is not a regular file", rel)
	case errors.Is(err, secassesssvc.ErrTooLarge):
		return rel, nil, "", "", fmt.Errorf("%s is over the %d MiB size cap, so it would not be read", rel, secassess.MaxModelBytesCeiling>>20)
	case err != nil:
		return rel, nil, "", "", err
	}
	var head struct {
		Schema string `json:"schema"`
		RunID  string `json:"run_id"`
	}
	if jerr := json.Unmarshal(data, &head); jerr != nil {
		return rel, data, "", "", errors.New("the file is not JSON, so it would not be read")
	}
	contract, known := secassess.ContractOfSchema(head.Schema)
	if _, checked := securityAssessChecks[contract]; !known || !checked {
		return rel, data, "", "", fmt.Errorf("the file's schema is %q; it must be %s", secassess.CleanText(head.Schema, 60), securityAssessSchemaWords())
	}
	switch {
	case runFlag != "":
		runID = runFlag
	case secassess.ValidRunID(filepath.Base(filepath.Dir(filepath.FromSlash(rel)))):
		runID = filepath.Base(filepath.Dir(filepath.FromSlash(rel)))
	default:
		runID = head.RunID
	}
	if !secassess.ValidRunID(runID) {
		return rel, data, contract, "", errors.New("no run id: pass --run, or keep the file in its run folder")
	}
	return rel, data, contract, runID, nil
}

// runSecurityAssessCheck is the command's body: it prints the report to out and
// returns errSecurityAssessCheck when anything would be refused or left out.
func runSecurityAssessCheck(out io.Writer, project, path, runFlag string, asJSON bool) error {
	projectAbs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	rel, data, contract, runID, err := securityAssessCheckInput(projectAbs, path, runFlag)
	if err != nil {
		return err
	}
	chk, err := secassesssvc.NewRefChecker(projectAbs, time.Now().Add(secassesssvc.RefDeadline), nil)
	if err != nil {
		return fmt.Errorf("the project folder cannot be read: %w", err)
	}
	defer chk.Close()
	opts := secassess.DefaultValidateOptions(contract, runID)
	// The check reads no settings, so it reads at the largest size the setting
	// allows and says so when the file is over the default cap.
	opts.Redact, opts.Refs, opts.MaxBytes = scrub.New().String, chk, secassess.MaxModelBytesCeiling
	// What a contract adds to the options beyond the defaults (a retest's findings).
	note := ""
	if prepare := securityAssessChecks[contract].prepare; prepare != nil {
		note = prepare(projectAbs, runID, data, &opts)
	}
	rep := secassess.Validate(data, opts).Report
	if len(data) > secassess.MaxModelBytes {
		note = joinNotes(note, fmt.Sprintf("The file is %d MiB. Observer refuses a file over its size cap, which is %d MiB unless the setting model_max_mib was raised; this check does not read your settings.", (len(data)+(1<<20)-1)>>20, secassess.MaxModelBytes>>20))
	}

	var issues []secassess.Issue
	for _, is := range rep.Issues {
		if securityAssessCheckRow(contract, is.Row) {
			issues = append(issues, is)
		}
	}
	clean := rep.State == secassess.ValidationValid && !hasNonWarn(issues)
	if asJSON {
		js := securityAssessCheckJS{File: rel, Schema: contract.Schema(), Run: runID, State: string(rep.State), Fatal: rep.Fatal, Issues: issues, More: rep.IssuesMore, Refs: rep.Refs, Counts: map[string]countsJSON{}, Note: note}
		for k, c := range rep.Counts {
			js.Counts[k] = countsJSON{Read: c.Read, Refused: c.Refused, LeftOut: c.LeftOut, Kept: c.Kept}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(js); err != nil {
			return err
		}
	} else {
		writeSecurityAssessCheck(out, rel, contract, runID, rep, issues)
		if note != "" {
			_, _ = fmt.Fprintln(out, note)
		}
	}
	if !clean {
		return errSecurityAssessCheck
	}
	return nil
}

// joinNotes joins two notes on one line, leaving out an empty one.
func joinNotes(a, b string) string {
	if a == "" || b == "" {
		return a + b
	}
	return a + " " + b
}

// hasNonWarn reports whether any issue refused or dropped something.
func hasNonWarn(issues []secassess.Issue) bool {
	for _, is := range issues {
		if is.Severity != secassess.SevWarn {
			return true
		}
	}
	return false
}

// writeSecurityAssessCheck prints the report as plain lines.
func writeSecurityAssessCheck(out io.Writer, rel string, c secassess.Contract, runID string, rep secassess.Report, issues []secassess.Issue) {
	_, _ = fmt.Fprintf(out, "%s: schema %s, run %s\n", rel, c.Schema(), runID)
	switch rep.State {
	case secassess.ValidationInvalid:
		_, _ = fmt.Fprintln(out, "Not read: the whole file would be refused (see below).")
	case secassess.ValidationPartial:
		refused, left, dropped := 0, 0, 0
		for _, cnt := range rep.Counts {
			refused += cnt.Refused
			left += cnt.LeftOut
		}
		for _, is := range issues {
			if is.Severity == secassess.SevDropped {
				dropped++
			}
		}
		_, _ = fmt.Fprintf(out, "Read, with items left out: %d refused, %d past a cap and %d fields or entries left out (see below).\n", refused, left, dropped)
	default:
		_, _ = fmt.Fprintln(out, "Read without anything refused or left out.")
	}
	if securityAssessChecks[c].refs {
		t := rep.Refs
		_, _ = fmt.Fprintf(out, "References: %d found near the cited line, %d location exists but nothing matched near the cited line, %d text not in the cited lines, %d missing, %d malformed, %d not looked at.\n",
			t.Found, t.Exists, t.ClaimedNotFound, t.Missing, t.Invalid, t.Unchecked)
	}
	for i, is := range issues {
		if i == securityAssessCheckMaxLines {
			_, _ = fmt.Fprintf(out, "... %d more\n", len(issues)-i+rep.IssuesMore)
			break
		}
		where := ""
		if is.Path != "" {
			where = " " + is.Path + ":"
		}
		_, _ = fmt.Fprintf(out, "- [%s %s]%s %s\n", is.Row, is.Severity, where, is.Message)
	}
	_, _ = fmt.Fprintln(out, "This checks structure and file references only; it does not check that the reasoning is right.")
}
