package store

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestCloudEvidenceSettingsValidation(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"legacy", "", true},
		{"null", "null", false},
		{"partial", `{"version":1}`, false},
		{"explicit zeros", `{"version":1,"user_messages":0,"assistant_messages":0,"failure_classes":0,"action_summaries":0,"excerpt_bytes":128,"milestones":false,"outcomes":false}`, true},
		{"over budget", `{"version":1,"user_messages":20,"assistant_messages":1,"failure_classes":0,"action_summaries":0,"excerpt_bytes":128,"milestones":false,"outcomes":false}`, false},
		{"future", `{"version":2,"user_messages":0,"assistant_messages":0,"failure_classes":0,"action_summaries":0,"excerpt_bytes":128,"milestones":false,"outcomes":false}`, false},
		{"null boolean", `{"version":1,"user_messages":0,"assistant_messages":0,"failure_classes":0,"action_summaries":0,"excerpt_bytes":128,"milestones":null,"outcomes":false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCloudEvidenceSettings(tc.raw)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestCloudEvidenceSettingsAreFrozenOnReceipt(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	settings := DefaultCloudEvidenceSettings()
	settings.UserMessages, settings.AssistantMessages, settings.FailureClasses = 10, 10, 0
	p := CloudEnrichPolicy{Level: CloudEnrichExcerpts, Background: true, EvidenceSettings: &settings}
	if err := s.SetCloudEnrichPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok || got.EvidenceSettings == nil || *got.EvidenceSettings != settings {
		t.Fatalf("policy: %+v %v", got, err)
	}
	raw, err := settings.JSON()
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{AccountPseudonym: "a", Purpose: cloudPurposeContextEnrichment, UploadDigest: "digest", EvidenceSettingsJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	p.Level = CloudEnrichTitles
	if err := s.SetCloudEnrichPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	r, ok, err := s.GetCloudConsentReceipt(ctx, id)
	if err != nil || !ok || r.EvidenceSettingsJSON != raw {
		t.Fatalf("receipt changed: %+v %v", r, err)
	}
	got, _, err = s.GetCloudEnrichPolicy(ctx)
	if err != nil || *got.EvidenceSettings != settings.ForLevel(CloudEnrichTitles) {
		t.Fatalf("title clamp: %+v %v", got, err)
	}
}

func TestSelectedAssistantMessagesExcludeOtherContent(t *testing.T) {
	s, database := cloudTestStore(t)
	seedEligibleSession(t, s, "selected-texts")
	ctx := context.Background()
	for i, row := range []struct {
		kind, message, body string
		side                int
	}{
		{"assistant_message", "one", "first block", 0},
		{"assistant_message", "one", "last block", 0},
		{"assistant_message", "two", "latest reply", 0},
		{"assistant_message", "child", "sidechain content must not appear", 1},
		{"run_command", "tool", "tool content must not appear", 0},
		{"user_prompt", "user", "user content excluded by zero", 0},
	} {
		if _, err := database.ExecContext(ctx, `INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, raw_tool_input, preceding_reasoning, source_file, source_event_id, message_id, is_sidechain)
            SELECT 'selected-texts', project_id, ?, ?, 'codex', 1, ?, 'raw payload must not appear', 'reasoning must not appear', 'settings-test', ?, ?, ? FROM sessions WHERE id='selected-texts'`,
			fmt.Sprintf("2026-09-13T10:00:%02dZ", i), row.kind, row.body, fmt.Sprint(i), row.message, row.side); err != nil {
			t.Fatal(err)
		}
	}
	settings := DefaultCloudEvidenceSettings()
	settings.UserMessages, settings.AssistantMessages, settings.FailureClasses = 0, 2, 0
	bundle, ok, err := s.LoadCloudEvidenceBundle(ctx, "selected-texts", CloudEvidenceRequest{IncludeTexts: true, EvidenceSettings: &settings})
	if err != nil || !ok {
		t.Fatalf("read: %v", err)
	}
	if len(bundle.Texts.UserPrompts) != 0 || len(bundle.Texts.Errors) != 0 || !reflect.DeepEqual(bundle.Texts.AssistantMessages, []string{"last block", "latest reply"}) {
		t.Fatalf("selected other content: %+v", bundle.Texts)
	}
}
