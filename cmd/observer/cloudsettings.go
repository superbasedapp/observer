package main

import (
	"context"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func cloudPrintConfiguredEnableExplanation(w io.Writer, background bool, level store.CloudEnrichLevel, settings store.CloudEvidenceSettings) {
	fmt.Fprintf(w, "Cloud Intelligence: %s; background enrichment enabled: %t.\n", level, background)
	fmt.Fprintf(w, "Each session may send up to %d user messages (including the first), %d latest assistant replies, and %d classified failures; message excerpts are capped at %d bytes and scrubbed.\n",
		settings.UserMessages, settings.AssistantMessages, settings.FailureClasses, settings.ExcerptBytes)
	fmt.Fprintf(w, "Tool activity summaries: up to %d; activity milestones: %t; test/build outcomes: %t. Session identity, duration, aggregate token/cost totals and activity counts remain included, plus a daily activity summary.\n",
		settings.ActionSummaries, settings.Milestones, settings.Outcomes)
	fmt.Fprintln(w, "Raw tool output, file contents, paths, and reasoning are excluded. Saving cancels queued background uploads from previous settings.")
	fmt.Fprintf(w, "%s (privacy policy v%s)\n", cloudcontract.ProviderPostureDisclosure, cloudcontract.ProviderPosturePolicyVersion)
	fmt.Fprintln(w, "Every send appears in the dashboard's What we sent ledger. Turn off any time with `observer cloud disable`.")
}

// buildCloudEnvelopeConfigured captures settings and generation in one policy
// read. Background consent also checks this generation atomically on insert.
func buildCloudEnvelopeConfigured(ctx context.Context, st *store.Store, sessionID string, purpose cloudcontract.Purpose, pricer *cost.Engine, generation int64) (cloudEnvelopeResult, error) {
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	if generation > 0 {
		want, eligible := policy.PurposeName()
		if !ok || !eligible || !policy.Background || policy.Generation != generation || want != string(purpose) {
			return cloudEnvelopeResult{}, store.ErrCloudBackgroundPolicyChanged
		}
	}
	return buildCloudEnvelopeWithSettings(ctx, st, sessionID, purpose, cloudFieldClasses(purpose), pricer, policy.EvidenceSettings)
}

func cloudSettingsForPurpose(settings *store.CloudEvidenceSettings, purpose cloudcontract.Purpose) (*store.CloudEvidenceSettings, string, error) {
	if settings == nil {
		return nil, "", nil
	}
	if err := settings.Validate(); err != nil {
		return nil, "", err
	}
	level := store.CloudEnrichTitles
	if purpose == cloudcontract.PurposeContextEnrichment {
		level = store.CloudEnrichExcerpts
	}
	effective := settings.ForLevel(level)
	raw, err := effective.JSON()
	return &effective, raw, err
}

func cloudApplyEvidenceSettings(input *cloudevidence.SessionInput, settings *store.CloudEvidenceSettings) {
	if settings == nil {
		return
	}
	if settings.ActionSummaries == 0 {
		input.Actions = nil
	}
	if !settings.Milestones {
		input.Milestones = nil
	}
	if !settings.Outcomes {
		input.Outcomes = cloudevidence.OutcomesInput{Build: "withheld_by_settings"}
	}
}

func cloudReceiptPreview(ctx context.Context, st *store.Store, receiptID, sessionID string, purpose cloudcontract.Purpose, pricer *cost.Engine) (cloudEnvelopeResult, error) {
	receipt, ok, err := st.GetCloudConsentReceipt(ctx, receiptID)
	if err != nil || !ok {
		return cloudEnvelopeResult{}, fmt.Errorf("preview receipt: receipt unavailable: %w", store.ErrCloudReceiptNotFound)
	}
	item, ok, err := st.FindCloudOutboxByReceipt(ctx, receiptID)
	if err != nil || !ok || item.SessionID != sessionID || receipt.Purpose != string(purpose) {
		return cloudEnvelopeResult{}, fmt.Errorf("preview receipt does not match this session and purpose")
	}
	settings, err := store.ParseCloudEvidenceSettings(receipt.EvidenceSettingsJSON)
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	return buildCloudEnvelopeWithSettings(ctx, st, sessionID, purpose, cloudReceiptFieldClasses(receipt.FieldClassesJSON), pricer, settings)
}
