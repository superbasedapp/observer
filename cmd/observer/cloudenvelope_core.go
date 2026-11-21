package main

import "github.com/marmutapp/superbased-observer/internal/cloudcontract"

// cloudenvelope_core.go holds the envelope result types the org intel rail
// (intelactions.go) and the Cloud Intelligence wiring (cloud.go,
// intelsubmit.go) share. They speak only internal/cloudcontract, which is
// core (operator ruling D-512: the org wire speaks it), so they stay in
// every build; a build without cloud.intelligence (-tags
// sbo_omit_cloud_intelligence) never fills them (intelsubmit_omit.go).

// cloudEnvelopeResult is the output of buildCloudEnvelope: the exact bytes a
// node previews AND uploads, their two digests, and a content-free summary.
type cloudEnvelopeResult struct {
	EvidenceSettingsJSON string
	Bytes                []byte
	Digests              cloudcontract.Digests
	CloudSession         string
	Actions              int
	Excerpts             int
	Purpose              cloudcontract.Purpose
	// Envelope is the built envelope these bytes were serialized from, so a
	// surface can summarize it without re-parsing the bytes. It is node-local
	// and is never a second serialization: Bytes above stays the one truth.
	Envelope *cloudcontract.Envelope
	// Budget is set when the envelope was fitted to the account's evidence
	// budget (the personal plane's preview and consent build, ruling R-AI1);
	// nil on a receipt rebuild or an org-plane build. Bytes above are already
	// the fitted bytes: the budget never adds a second serialization.
	Budget *cloudBudgetNote
}

// cloudBudgetNote is the content-free account of one evidence-budget fit.
type cloudBudgetNote struct {
	// BudgetTokens is the evidence budget fitted to (0 = no budget).
	BudgetTokens int
	// BudgetKnown is false when no sync has read the account's budget yet and
	// BudgetTokens is cloudcontract.DefaultEvidenceTokenBudget.
	BudgetKnown bool
	// EstimatedTokens is cloudcontract.EstimateEvidenceTokens of the bytes.
	EstimatedTokens int
	// UnfittedTokens is the estimate of the build before any step-down.
	UnfittedTokens int
	// SteppedDown reports that the bytes are a smaller build than the
	// developer's own settings produce; Rung names the ladder step.
	SteppedDown bool
	Rung        string
}

// orgIntelBuilt is one built org-plane envelope.
type orgIntelBuilt struct {
	OrgID   string
	Level   cloudcontract.EvidenceLevel
	Purpose cloudcontract.Purpose
	Result  cloudEnvelopeResult
}
