package cloudresult

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// ScrubNormalized secret-scrubs every SafeText field of a validated result and
// re-wraps each masked value into the opaque representation. NormalizeText
// both re-validates (controls/bidi already rejected) and re-bounds after any
// masking length change. On error it returns nr unchanged with the error.
func ScrubNormalized(nr cloudcontract.NormalizedResult) (cloudcontract.NormalizedResult, error) {
	out := cloudcontract.NormalizedResult{Confidence: nr.Confidence, SchemaVersion: nr.SchemaVersion}
	var err error
	if out.Title, err = ScrubField("title", nr.Title.String(), cloudcontract.MaxTitleBytes, true); err != nil {
		return nr, err
	}
	if out.Description, err = ScrubField("description", nr.Description.String(), cloudcontract.MaxDescriptionBytes, false); err != nil {
		return nr, err
	}
	if out.TaxonomyTags, err = ScrubList("taxonomy_tags", nr.TaxonomyTags, cloudcontract.MaxTagBytes); err != nil {
		return nr, err
	}
	if out.SuggestedTags, err = ScrubList("suggested_tags", nr.SuggestedTags, cloudcontract.MaxTagBytes); err != nil {
		return nr, err
	}
	if out.EvidenceRefs, err = ScrubList("evidence_refs", nr.EvidenceRefs, cloudcontract.MaxEvidenceRefBytes); err != nil {
		return nr, err
	}
	if out.Limitations, err = ScrubList("limitations", nr.Limitations, cloudcontract.MaxLimitationBytes); err != nil {
		return nr, err
	}
	// The five narrative lists are model prose like any other field: a
	// completion can reproduce a secret in one, so they go through the SAME
	// mask-and-re-normalize pass.
	nb := cloudcontract.MaxNarrativeItemBytes
	if out.WorkDone, err = ScrubList("work_done", nr.WorkDone, nb); err != nil {
		return nr, err
	}
	if out.PlansImplemented, err = ScrubList("plans_implemented", nr.PlansImplemented, nb); err != nil {
		return nr, err
	}
	if out.IssuesFound, err = ScrubList("issues_found", nr.IssuesFound, nb); err != nil {
		return nr, err
	}
	if out.Failures, err = ScrubList("failures", nr.Failures, nb); err != nil {
		return nr, err
	}
	if out.NextSteps, err = ScrubList("next_steps", nr.NextSteps, nb); err != nil {
		return nr, err
	}
	return out, nil
}

// ScrubField masks every secret scrub finds in s and re-normalizes the masked
// text as the SafeText of field, bounded to maxBytes (required rejects empty).
func ScrubField(field, s string, maxBytes int, required bool) (cloudcontract.SafeText, error) {
	masked, _ := scrub.MaskSecrets(s, func(scrub.TypedFinding) bool { return true })
	return cloudcontract.NormalizeText(field, masked, maxBytes, required)
}

// ScrubList applies ScrubField to every item of list, naming each item
// "<field>[<i>]" in an error. An empty list stays nil.
func ScrubList(field string, list []cloudcontract.SafeText, maxBytes int) ([]cloudcontract.SafeText, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]cloudcontract.SafeText, 0, len(list))
	for i, v := range list {
		st, err := ScrubField(fmt.Sprintf("%s[%d]", field, i), v.String(), maxBytes, true)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}
