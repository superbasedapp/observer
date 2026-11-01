package secverify

import (
	"context"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// secretRule is how verify treats one scrub detector type.
type secretRule struct {
	Severity   Severity
	Confidence Confidence
	Action     Action
}

// secretRules maps scrub's typed secret detectors to a CI judgement.
// Shape-certain credentials (a token whose format is the evidence) deny;
// key-context rows (a value assigned to a name like "password") flag,
// because placeholders and examples share that shape. The entropy
// heuristic is never used here (security plan 5.3: never for blocking).
// A type missing from this table (a row scrub adds later) takes
// secretRuleDefault.
var secretRules = map[string]secretRule{
	"github_pat":                 {SeverityCritical, ConfidenceHigh, ActionDeny},
	"github_pat_fine":            {SeverityCritical, ConfidenceHigh, ActionDeny},
	"aws_access_key":             {SeverityCritical, ConfidenceHigh, ActionDeny},
	"aws_secret_key":             {SeverityCritical, ConfidenceHigh, ActionDeny},
	"private_key_block":          {SeverityCritical, ConfidenceHigh, ActionDeny},
	"gcp_api_key":                {SeverityHigh, ConfidenceHigh, ActionDeny},
	"slack_token":                {SeverityHigh, ConfidenceHigh, ActionDeny},
	"api_key_prefixed":           {SeverityHigh, ConfidenceHigh, ActionDeny},
	"jwt":                        {SeverityHigh, ConfidenceMedium, ActionDeny},
	"connection_string_password": {SeverityHigh, ConfidenceMedium, ActionDeny},
	"bearer_token":               {SeverityHigh, ConfidenceMedium, ActionFlag},
	"api_key_named":              {SeverityMedium, ConfidenceMedium, ActionFlag},
	"api_key_assignment":         {SeverityMedium, ConfidenceMedium, ActionFlag},
	"secret_assignment":          {SeverityMedium, ConfidenceMedium, ActionFlag},
	"json_secret_value":          {SeverityMedium, ConfidenceMedium, ActionFlag},
	"env_secret_value":           {SeverityMedium, ConfidenceMedium, ActionFlag},
	"export_secret":              {SeverityMedium, ConfidenceMedium, ActionFlag},
}

var secretRuleDefault = secretRule{SeverityMedium, ConfidenceMedium, ActionFlag}

// knownExampleSecrets are published documentation values that never fire
// (security plan 5.3: "a known-example key list ... never fires").
var knownExampleSecrets = map[string]bool{
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,
}

// detectSecrets runs scrub's typed, pattern-certain secret detectors over
// each run of consecutive added lines (so a multi-line private key block is
// seen whole) and reports each hit at the line it starts on. The matched
// value is used to locate the line and is then dropped: it never reaches a
// finding, a fingerprint or the report.
func detectSecrets(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "secrets", Status: CoverageComplete}
	var out []Finding
	for _, f := range in.Files {
		if ctx.Err() != nil {
			cov.Status = CoverageFailed
			cov.Note = "cancelled before every file was read"
			break
		}
		if f.Status == StatusDeleted {
			continue
		}
		if f.Binary {
			// A skipped file is not "checked": a required secrets check over
			// a change with an unread file is partial, never complete.
			cov.Skipped++
			cov.SkipReason = "binary files are not read"
			if cov.Status == CoverageComplete {
				cov.Status = CoveragePartial
				cov.Note = "a changed file was binary and was not read"
			}
			continue
		}
		cov.Files++
		if f.Partial {
			cov.Status = CoveragePartial
			cov.Note = "a file's added text was over the cap and was read only in part"
		}
		occ := map[string]int{}
		for _, blk := range addedBlocks(f.Added) {
			from := 0
			for _, tf := range scrub.DetectSecrets(blk.text) {
				if !tf.Certain || tf.Class != scrub.ClassSecret || knownExampleSecrets[tf.Value] {
					continue
				}
				line := blk.first
				if i := strings.Index(blk.text[from:], tf.Value); i >= 0 {
					line += strings.Count(blk.text[:from+i], "\n")
					from += i + len(tf.Value)
				}
				r, ok := secretRules[tf.Type]
				if !ok {
					r = secretRuleDefault
				}
				rule := "secret/" + tf.Type
				out = append(out, Finding{
					RuleID:        rule,
					Detector:      "secrets",
					Category:      CategorySecret,
					Severity:      r.Severity,
					Confidence:    r.Confidence,
					Path:          f.Path,
					Line:          line,
					Message:       "This change adds a value with the shape of a " + typeLabel(tf.Type) + ". Remove it from the change, rotate it, and load it from the environment or a secret store.",
					Fingerprint:   fingerprint(rule, f.Path, occ[rule]),
					DefaultAction: r.Action,
				})
				occ[rule]++
			}
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// typeLabel renders a scrub type name for a message ("aws_access_key" ->
// "aws access key"). The names come from scrub's closed table; anything
// outside a safe character set is replaced all the same.
func typeLabel(t string) string {
	return strings.ReplaceAll(clipSafe(t, 40), "_", " ")
}

// addedBlock is a run of added lines with consecutive line numbers.
type addedBlock struct {
	first int
	text  string
}

func addedBlocks(lines []AddedLine) []addedBlock {
	var out []addedBlock
	var b strings.Builder
	first, prev := 0, -1
	flush := func() {
		if prev >= 0 {
			out = append(out, addedBlock{first: first, text: b.String()})
		}
		b.Reset()
	}
	for _, l := range lines {
		if prev < 0 || l.N != prev+1 {
			flush()
			first = l.N
		} else {
			b.WriteByte('\n')
		}
		b.WriteString(l.Text)
		prev = l.N
	}
	flush()
	return out
}
