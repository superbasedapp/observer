package cloudevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// BuildEnvelope constructs a schema-valid cloudcontract.Envelope from input for
// the named plane, applying every privacy rule from the plan and telemetry plan
// §6:
//
//   - the session's data-authority MUST match the plane being built for, else
//     the build is refused (INV-1): org-authority data builds only for
//     PlaneOrg, personal-authority data only for PlanePersonal, and unknown
//     authority for neither. The decision is the closed six-row
//     planeEligibility table, not an if/else ladder. plane is required; the
//     empty zero value matches no row and is refused.
//   - cloud IDs must be random pseudonyms — path-like or PK-like values are
//     rejected;
//   - action/milestone/context arrays are bounded, overflow summarized as a
//     count (never as content);
//   - paths default to extension/category; salted path hashes appear only
//     under the path-correlation grant;
//   - every optional excerpt and the feedback note are scrubbed and capped;
//   - user feedback and context excerpts appear only when their grant/flag
//     names them;
//   - the granted purposes are recorded (sorted, deduped) as disclosure.
//
// The returned envelope has empty digest fields — digests are a serialization
// concern owned by Serialize (the one function that produces preview and
// upload bytes).
func BuildEnvelope(input SessionInput, plane cloudcontract.Plane, opts BuildOptions) (*cloudcontract.Envelope, error) {
	if !eligibleForPlane(plane, input.Authority) {
		return nil, fmt.Errorf("cloudevidence.BuildEnvelope: authority %q (v%d) is ineligible for the %q plane (INV-1)", input.Authority.Authority, input.Authority.Version, plane)
	}
	if opts.ScrubberVersion == "" {
		return nil, fmt.Errorf("cloudevidence.BuildEnvelope: ScrubberVersion is required")
	}
	if err := validateCloudID("cloud_session_id", input.CloudSessionID); err != nil {
		return nil, fmt.Errorf("cloudevidence.BuildEnvelope: %w", err)
	}
	if err := validateCloudID("cloud_project_id", input.CloudProjectID); err != nil {
		return nil, fmt.Errorf("cloudevidence.BuildEnvelope: %w", err)
	}

	// The model string is the developer's, not ours (a custom endpoint, a local
	// Ollama tag, a gateway alias), so it is mapped onto the CLOSED family
	// vocabulary rather than copied (A2). A session with no captured model — or
	// one on a model this table does not know — is honestly "unknown"; a missing
	// local label must not cost the insight, and an unrecognized one must not
	// cost the promise.
	modelFamily := NormalizeModelFamily(input.ModelFamily)

	env := &cloudcontract.Envelope{
		SchemaVersion:   cloudcontract.EnvelopeSchemaVersion,
		CloudSessionID:  input.CloudSessionID,
		CloudProjectID:  input.CloudProjectID,
		Tool:            input.Tool,
		ModelFamily:     modelFamily,
		StartedAtBucket: input.StartedAtBucket,
		DurationSeconds: input.DurationSeconds,
		Metrics: cloudcontract.MetricsBlock{
			TokensIn:              input.Metrics.TokensIn,
			TokensOut:             input.Metrics.TokensOut,
			CacheReadTokens:       input.Metrics.CacheReadTokens,
			CostUSD:               input.Metrics.CostUSD,
			DeterministicScore:    input.Metrics.DeterministicScore,
			RedundancyRatio:       input.Metrics.RedundancyRatio,
			ErrorRate:             input.Metrics.ErrorRate,
			ExplorationEfficiency: input.Metrics.ExplorationEfficiency,
			ContinuityScore:       input.Metrics.ContinuityScore,
		},
		Outcomes: cloudcontract.Outcomes{
			TestsRun:      input.Outcomes.TestsRun,
			TestsPassed:   input.Outcomes.TestsPassed,
			Build:         input.Outcomes.Build,
			TestsUnknown:  input.Outcomes.TestsUnknown,
			BuildsUnknown: input.Outcomes.BuildsUnknown,
		},
		ActivityMix:        buildActivityMix(input.ActivityMix),
		DisclosurePurposes: sortedUniquePurposes(opts.GrantedPurposes),
		ScrubberVersion:    opts.ScrubberVersion,
		Authority:          input.Authority,
	}

	overflow := &cloudcontract.Overflow{}

	emitPathHash := opts.PathCorrelation && len(opts.PathSalt) > 0
	actions, actionsOmitted := boundActions(input.Actions, input.ActionsTotal, emitPathHash, opts.PathSalt)
	env.Actions = actions
	overflow.ActionsOmitted = actionsOmitted

	milestones, milestonesOmitted := boundMilestones(input.Milestones)
	env.Milestones = milestones
	overflow.MilestonesOmitted = milestonesOmitted

	if opts.IncludeUserFeedback && input.UserFeedback != nil {
		note := input.UserFeedback.Note
		if note != "" {
			if opts.Scrubber == nil {
				return nil, fmt.Errorf("cloudevidence.BuildEnvelope: user-feedback note requires a Scrubber")
			}
			note = scrub.TruncateN(opts.Scrubber.String(note), cloudcontract.MaxExcerptBytes)
		}
		env.UserFeedback = &cloudcontract.UserFeedback{Rating: input.UserFeedback.Rating, Note: note}
	}

	if admitted := admitExcerpts(input.Excerpts, opts); len(admitted) > 0 {
		if opts.Scrubber == nil {
			return nil, fmt.Errorf("cloudevidence.BuildEnvelope: context excerpts require a Scrubber")
		}
		excerpts, contextOmitted := boundExcerpts(admitted, opts.Scrubber)
		env.Context = excerpts
		overflow.ContextOmitted = contextOmitted
	}

	if overflow.ActionsOmitted > 0 || overflow.MilestonesOmitted > 0 || overflow.ContextOmitted > 0 {
		env.Overflow = overflow
	}

	if err := env.Validate(); err != nil {
		return nil, fmt.Errorf("cloudevidence.BuildEnvelope: built an invalid envelope: %w", err)
	}
	return env, nil
}

// boundActions caps the action list at MaxActions, deriving each action's
// category from its path and (when granted) emitting a salted path hash. It
// returns the bounded list and how many actions were omitted.
//
// Over-cap lists are SAMPLED with an even stride across the WHOLE session
// (first and last always kept), not truncated at the head. Head truncation was
// a real defect, not a stylistic choice: a 1718-action session shipped its
// first 256 actions — the `/clear`, the caveats, and the opening reads — and
// the model never saw the work.
//
// total is the session's whole action population (0 ⇒ `in` is the population).
// The omission count is always computed against that population, so a caller
// that ALREADY sampled — the store's SQL-side stride, which is what lets a
// 30,000-action session be sampled across rather than truncated — still reports
// the true remainder rather than zero.
func boundActions(in []ActionInput, total int, emitPathHash bool, salt []byte) ([]cloudcontract.Action, int) {
	population := len(in)
	if total > population {
		population = total
	}
	if len(in) > cloudcontract.MaxActions {
		in = strideSample(in, cloudcontract.MaxActions)
	}
	omitted := population - len(in)
	out := make([]cloudcontract.Action, 0, len(in))
	for _, a := range in {
		category := a.Category
		if category == "" {
			category = deriveCategory(a.Path)
		}
		// Both labels pass the SAME closed-vocabulary gate the activity mix
		// applies to its keys (A2): an action_type of "payroll.csv" counted as
		// "unclassified" in the mix while shipping verbatim right here.
		act := cloudcontract.Action{
			Ref:      a.Ref,
			Kind:     NormalizeActionKind(a.Kind),
			Category: NormalizeCategory(category),
			Status:   a.Status,
		}
		if emitPathHash && a.Path != "" {
			act.PathHash = saltedPathHash(salt, a.Path)
		}
		out = append(out, act)
	}
	return out, omitted
}

// boundMilestones caps the milestone list at MaxMilestones.
func boundMilestones(in []MilestoneInput) ([]cloudcontract.Milestone, int) {
	omitted := 0
	if len(in) > cloudcontract.MaxMilestones {
		omitted = len(in) - cloudcontract.MaxMilestones
		in = in[:cloudcontract.MaxMilestones]
	}
	out := make([]cloudcontract.Milestone, 0, len(in))
	for _, m := range in {
		out = append(out, cloudcontract.Milestone{Ref: m.Ref, Kind: m.Kind, ElapsedSeconds: m.ElapsedSeconds})
	}
	return out, omitted
}

// admitExcerpts is the CONSENT gate for context: which of the selected
// excerpts the granted purposes / field classes let into the envelope. It is
// an ordered rule table, first match wins:
//
//  1. bounded_context_enrichment granted  -> every selected excerpt;
//  2. first_user_prompt_excerpt class     -> ONLY the first excerpt whose source
//     granted (structural purpose alone)     is first_user_prompt, at most one -
//     the "Title only" level's set;
//  3. otherwise                           -> nothing.
//
// Row 2 is what makes the "Title only" level's disclosure ("a structural
// summary and your first prompt, nothing else") true on the wire: before it
// existed (2026-09-16) a structural build carried NO context at all, so the
// model titled sessions from the action sample alone - the opening reads and
// the closing test runs - while every consent screen promised the first
// prompt. The hosted gate mirrors row 2 with
// cloudcontract.Envelope.ContextIsFirstPromptOnly.
func admitExcerpts(in []ExcerptInput, opts BuildOptions) []ExcerptInput {
	switch {
	case len(in) == 0:
		return nil
	case opts.hasPurpose(cloudcontract.PurposeContextEnrichment):
		return in
	case opts.hasFieldClass(cloudcontract.FieldClassFirstUserPrompt):
		for _, e := range in {
			if e.Source == SourceFirstUserPrompt {
				return []ExcerptInput{e}
			}
		}
		return nil
	default:
		return nil
	}
}

// boundExcerpts caps the excerpt list at MaxContextExcerpts, scrubbing and
// length-capping each one. Empty (or fully-scrubbed-to-empty) excerpts are
// dropped.
func boundExcerpts(in []ExcerptInput, sc *scrub.Scrubber) ([]cloudcontract.ContextExcerpt, int) {
	omitted := 0
	if len(in) > cloudcontract.MaxContextExcerpts {
		omitted = len(in) - cloudcontract.MaxContextExcerpts
		in = in[:cloudcontract.MaxContextExcerpts]
	}
	out := make([]cloudcontract.ContextExcerpt, 0, len(in))
	for _, e := range in {
		capBytes := e.CapBytes
		if capBytes <= 0 || capBytes > cloudcontract.MaxExcerptBytes {
			capBytes = cloudcontract.MaxExcerptBytes
		}
		text := scrub.TruncateN(sc.String(e.Text), capBytes)
		out = append(out, cloudcontract.ContextExcerpt{
			Source:         e.Source,
			Text:           text,
			LengthCapBytes: capBytes,
		})
	}
	return out, omitted
}

// deriveCategory returns p's file extension when it is a MEMBER of the closed
// extension vocabulary, else "other". The raw path is never returned.
//
// WHY MEMBERSHIP AND NOT A SHAPE CHECK (A2). This used to accept any short
// unaccented-alphanumeric tail, on the reasoning that a real extension looks
// like that. So does a codename: `plan.acmemerger` shipped "acmemerger", and
// `notes.payroll` shipped "payroll". A shape check cannot tell a file extension
// from a word, because there is no shape that distinguishes them — only a table
// we wrote can. See closedExtensions in normalize.go.
func deriveCategory(p string) string {
	np := normalizePath(p)
	if np == "" {
		return LabelOther
	}
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(np), "."))
	if !closedExtensions[ext] {
		return LabelOther
	}
	return ext
}

// normalizePath converts separators to forward slashes and cleans p. It is
// used both for category derivation and (before hashing) for stable path
// hashes; it never returns the path to any envelope field directly.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	return p
}

// saltedPathHash returns a per-account salted SHA-256 hash of the normalized
// path, prefixed "sha256:". The salt separates accounts so the same path on
// two accounts does not collide, and the raw path is never recoverable.
func saltedPathHash(salt []byte, p string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte{0}) // domain separator between salt and path
	h.Write([]byte(normalizePath(p)))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// sortedUniquePurposes returns the granted purposes sorted and deduped, so the
// disclosure list is deterministic regardless of caller order.
func sortedUniquePurposes(in []cloudcontract.Purpose) []cloudcontract.Purpose {
	seen := make(map[cloudcontract.Purpose]bool, len(in))
	out := make([]cloudcontract.Purpose, 0, len(in))
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// validateCloudID rejects empty, path-like, or purely-numeric (DB-primary-key-
// like) cloud IDs. Random pseudonyms (UUID/hex/base32) pass; a filesystem path
// or a bare row id does not.
func validateCloudID(field, id string) error {
	if id == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(id) > cloudcontract.MaxCloudIDBytes {
		return fmt.Errorf("%s is %d bytes, exceeds max %d", field, len(id), cloudcontract.MaxCloudIDBytes)
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("%s %q looks like a filesystem path", field, id)
	}
	// Windows drive-letter prefix (e.g. "C:...").
	if len(id) >= 2 && id[1] == ':' {
		return fmt.Errorf("%s %q looks like a filesystem path", field, id)
	}
	if isAllDigits(id) {
		return fmt.Errorf("%s %q looks like a database primary key; use a random pseudonym", field, id)
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
