package promptjudgecases

// SecretSample carries a pattern-certain secret (a GitHub token shape) that
// the node lane's secret gate recognises.
const SecretSample = "deploy it with token=ghp_AbCdEfGhIjKlMnOpQrStUvWx1234 please"

// SecretGateCase is one node-lane secret-gate case: a planeb.admission body
// and the outcome the node lane must give SecretSample, with the judge never
// called.
type SecretGateCase struct {
	Name  string
	Draft string
	// WantAction / WantBasis are promptadmit's Action and Basis values.
	WantAction string
	WantBasis  string
	// WantReasonSub is a substring of the outcome's reason.
	WantReasonSub string
}

// SecretGateCases is the shared table.
var SecretGateCases = []SecretGateCase{
	{
		Name:          "strict enforce refuses at the secret gate",
		Draft:         `{"admission":{"mode":"enforce","strict":true,"criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]},"node_lane":true}`,
		WantAction:    "block",
		WantBasis:     "secret_gate",
		WantReasonSub: "secret gate kept it from the remote judge",
	},
	{
		Name:          "not strict: the flag floor flags it, never judged",
		Draft:         `{"admission":{"mode":"enforce","criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]},"node_lane":true}`,
		WantAction:    "flag",
		WantBasis:     "flag",
		WantReasonSub: "not sent to the remote judge",
	},
	{
		Name:          "the org chose deny for secrets: refused, never judged",
		Draft:         `{"admission":{"mode":"enforce","secret_remote_judge":"deny","criteria":[{"id":"AD-100","type":"custom","decision":"allow","definition":"x"}]},"node_lane":true}`,
		WantAction:    "block",
		WantBasis:     "deny",
		WantReasonSub: "not sent to the remote judge",
	},
}
