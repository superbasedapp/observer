package main

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestCloudConfiguredEnvelopeAndReceiptRebuild(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "configured", "personal")
	s, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	legacy, err := buildCloudEnvelopeFor(ctx, s, "configured", cloudcontract.PurposeContextEnrichment, cloudFieldClasses(cloudcontract.PurposeContextEnrichment), nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := store.DefaultCloudEvidenceSettings()
	if settings.ActionSummaries != cloudcontract.MaxActions || settings.UserMessages+settings.AssistantMessages+settings.FailureClasses > cloudcontract.MaxContextExcerpts {
		t.Fatal("policy limits drifted from contract")
	}
	settings.UserMessages, settings.AssistantMessages, settings.FailureClasses, settings.ActionSummaries = 0, 0, 0, 0
	settings.Milestones, settings.Outcomes = false, false
	if err := s.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{Level: store.CloudEnrichExcerpts, Background: true, EvidenceSettings: &settings}); err != nil {
		t.Fatal(err)
	}
	p, _, _ := s.GetCloudEnrichPolicy(ctx)
	zero, err := buildCloudEnvelopeConfigured(ctx, s, "configured", cloudcontract.PurposeContextEnrichment, nil, p.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if zero.Actions != 0 || zero.Excerpts != 0 || len(zero.Envelope.Milestones) != 0 || zero.EvidenceSettingsJSON == "" {
		t.Fatalf("zero categories were not excluded: %+v", zero)
	}
	if err := s.SetCloudEnrichPolicy(ctx, store.CloudEnrichPolicy{Level: store.CloudEnrichTitles, Background: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := buildCloudEnvelopeConfigured(ctx, s, "configured", cloudcontract.PurposeContextEnrichment, nil, p.Generation); !errors.Is(err, store.ErrCloudBackgroundPolicyChanged) {
		t.Fatalf("stale subprocess: %v", err)
	}
	frozen, err := store.ParseCloudEvidenceSettings(zero.EvidenceSettingsJSON)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := buildCloudEnvelopeWithSettings(ctx, s, "configured", cloudcontract.PurposeContextEnrichment, cloudFieldClasses(cloudcontract.PurposeContextEnrichment), nil, frozen)
	if err != nil || rebuilt.Digests != zero.Digests {
		t.Fatalf("frozen rebuild drift: %v", err)
	}
	legacyAgain, err := buildCloudEnvelopeFor(ctx, s, "configured", cloudcontract.PurposeContextEnrichment, cloudFieldClasses(cloudcontract.PurposeContextEnrichment), nil)
	if err != nil || legacyAgain.Digests != legacy.Digests {
		t.Fatalf("legacy rebuild drift: %v", err)
	}
}

func TestCloudDisablePreservesEvidencePreferences(t *testing.T) {
	cfg, dbPath, _ := writeCloudTestConfig(t)
	settings := store.DefaultCloudEvidenceSettings()
	settings.UserMessages, settings.AssistantMessages, settings.FailureClasses = 10, 8, 2
	raw, err := settings.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"enable", "--with-excerpts", "--evidence-settings", raw},
		{"disable"},
		{"enable", "--with-excerpts"},
	} {
		args = append(args, "--config", cfg, "--yes")
		if args[0] == "enable" {
			args = append(args, "--base-url", "http://cloud.invalid")
		}
		if output, err := runCloudCmd(t, args...); err != nil {
			t.Fatalf("%s: %v\n%s", args[0], err, output)
		}
	}
	s, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	p, ok, err := s.GetCloudEnrichPolicy(context.Background())
	if err != nil || !ok || p.EvidenceSettings == nil || *p.EvidenceSettings != settings {
		t.Fatalf("preferences lost: %+v %v", p, err)
	}
}
