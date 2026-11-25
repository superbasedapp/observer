package admission

import "strings"

// CriterionUnaccounted is the criterion of the verdict an admission seam
// gives a request that carries user content its admission view cannot read
// (an image, a PDF, a legacy prompt field, an undecoded body): refused under
// enforce, recorded as the shadow finding under observe (hosted AI gateway
// security review, finding H1, lead decision L-180). The AI gateway's app
// gate and the node's hosted-app admission both use it; the content labels
// come from internal/promptturn.AdmissionView.
const CriterionUnaccounted = "admission_unaccounted"

// UnaccountedReason is the verdict's reason: the content's type labels,
// never the content.
func UnaccountedReason(labels []string) string {
	return "the request carries content the admission policy cannot read (" + strings.Join(labels, ", ") + ")"
}
