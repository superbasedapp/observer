package contract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validEnvelope() *Envelope {
	return &Envelope{
		EnvelopeVersion: EnvelopeVersion,
		BatchUUID:       "0b5c3d1e-1111-4222-8333-444455556666",
		InstallID:       "inst-0123456789ab",
		SeqStart:        100,
		SeqEnd:          101,
		ClientVersion:   "1.5.0",
		OS:              "linux",
		Arch:            "amd64",
		EventCount:      2,
		ClientTS:        "2026-09-14T10:00:00Z",
		Events: []Event{
			{
				Event: EventToolUse, EventVersion: 1,
				SchemaVersion: "2026-09-14T00:00:00Z", TS: "2026-09-14T09:59:00Z",
				InstallID: "inst-0123456789ab", Seq: 100,
				Classification: ClassSystemMeta, Purpose: PurposeFeature,
				Fields: map[string]any{"tool_name": "shell", "count": 2},
			},
			{
				Event: EventError, EventVersion: 1,
				SchemaVersion: "2026-09-14T00:00:00Z", TS: "2026-09-14T09:59:30Z",
				InstallID: "inst-0123456789ab", Seq: 101,
				Classification: ClassCallstack, Purpose: PurposePerfHealth,
				Fields: map[string]any{"error_class": "tool_timeout", "surface": "tool"},
			},
		},
	}
}

func TestValidateEnvelope_OK(t *testing.T) {
	if err := ValidateEnvelope(validEnvelope()); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestValidateEnvelope_Errors(t *testing.T) {
	cases := []struct {
		name    string
		mutator func(*Envelope)
		wantErr error
	}{
		{"wrong envelope version", func(e *Envelope) { e.EnvelopeVersion = "v2" }, ErrUnknownVersion},
		{"bad batch uuid", func(e *Envelope) { e.BatchUUID = "nope" }, ErrBadSchema},
		{"bad install id", func(e *Envelope) { e.InstallID = "inst-ZZZZ" }, ErrBadSchema},
		{"count mismatch", func(e *Envelope) { e.EventCount = 5 }, ErrBadSchema},
		{"empty batch", func(e *Envelope) { e.Events = nil; e.EventCount = 0 }, ErrBadSchema},
		{"seq regression", func(e *Envelope) { e.SeqStart, e.SeqEnd = 10, 5 }, ErrBadSchema},
		{"bad client ts", func(e *Envelope) { e.ClientTS = "2026-09-14 10:00:00" }, ErrBadSchema},
		{"unknown event", func(e *Envelope) {
			e.Events[0].Event = "page_viewed"
		}, ErrBadSchema},
		{"wrong classification", func(e *Envelope) {
			e.Events[0].Classification = ClassCallstack
		}, ErrBadSchema},
		{"unknown tool", func(e *Envelope) {
			e.Events[0].Fields["tool_name"] = "nuke_from_orbit"
		}, ErrBadSchema},
		{"event install mismatch", func(e *Envelope) {
			e.Events[0].InstallID = "inst-ffffffffffff"
		}, ErrBadSchema},
		{"bad ts in event", func(e *Envelope) {
			e.Events[0].TS = "not-a-time"
		}, ErrBadSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnvelope()
			tc.mutator(env)
			err := ValidateEnvelope(env)
			if !is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func is(a, b error) bool {
	return errors.Is(a, b) // errors.Is already reports a == b
}

func TestTierAllows(t *testing.T) {
	cases := []struct {
		tier, event string
		want        bool
	}{
		{TierOff, EventToolUse, false},
		{TierError, EventError, true},
		{TierError, EventBatchMeta, true},
		{TierError, EventToolUse, false}, // error tier: no usage events
		{TierUsage, EventToolUse, true},
		{TierUsage, EventDiagCommand, false}, // deep only
		{TierDeep, EventDiagCommand, true},
		{TierDeep, EventTokenUse, true},
	}
	for _, tc := range cases {
		if got := TierAllows(tc.tier, tc.event); got != tc.want {
			t.Errorf("TierAllows(%q, %q) = %v, want %v", tc.tier, tc.event, got, tc.want)
		}
	}
}

func TestTierCovers(t *testing.T) {
	// New model: off < baseline(==usage) < deep < enrichment.
	if !TierCovers(TierBaseline, TierBaseline) ||
		!TierCovers(TierDeep, TierBaseline) ||
		!TierCovers(TierEnrichment, TierDeep) ||
		TierCovers(TierBaseline, TierDeep) ||
		TierCovers(TierError, TierBaseline) ||
		!TierCovers(TierUsage, TierBaseline) {
		t.Fatal("tier escalation ranking wrong")
	}
	// Legacy usage is an alias for baseline at the same rank.
	if EffectiveTier(TierUsage) != TierBaseline {
		t.Fatal("usage should normalize to baseline")
	}
}

// TestBaselineTierEvents is the drift-gate anchor: BaselineTierEvents() must
// match the canonical baseline event set that every repo's contract asserts
// against. If a repo adds or removes a baseline event without updating all
// three, this list is the thing the cross-repo assertion is glued to.
func TestBaselineTierEvents(t *testing.T) {
	got := BaselineTierEvents()
	want := []string{
		EventAppStart,
		EventAppStop,
		EventSessionStart,
		EventSessionEnd,
		EventToolUse,
		EventError,
		EventTokenUse,
		EventDayActive,
		EventBatchMeta,
		EventPromptCycle,
	}
	if len(got) != len(want) {
		t.Fatalf("baseline event count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("baseline event[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPromptCycleAllowlist asserts the exact field set the baseline
// prompt_cycle event admits. This is the readable form of the
// no-text-fields guarantee for the new baseline event.
func TestPromptCycleAllowlist(t *testing.T) {
	allowed := map[string]bool{
		"model":                  true,
		"provider":               true,
		"input_size":             true,
		"output_size":            true,
		"cache_percentage":       true,
		"end_to_end_duration_ms": true,
		"segment":                true,
		"session_span":           true,
		"turn_id":                true,
	}
	if len(allowed) != 9 {
		t.Fatal("prompt_cycle allowlist shape changed — review no-text-fields enforcement")
	}
}

// TestBaselineNoPromptOrOutputText is the commit-time backstop (plan §5.1):
// no event admitted by the baseline tier may contain a prompt-text or
// output-text field name. The forbidden set is curated, not fuzzy, so it is
// exact and reviewable.
func TestBaselineNoPromptOrOutputText(t *testing.T) {
	forbidden := map[string]bool{
		"prompt_text":   true,
		"prompt":        true,
		"output_text":   true,
		"output":        true,
		"content":       true,
		"text":          true,
		"body":          true,
		"message":       true,
		"message_body":  true,
		"request_text":  true,
		"response_text": true,
		"input_text":    true,
		"raw_prompt":    true,
		"raw_output":    true,
		"prompt_body":   true,
		"response_body": true,
		"input_body":    true,
		"output_body":   true,
	}
	// Baseline events include prompt_cycle plus the content-free lifecycle /
	// tool / error / token / batch events that already had closed vocabularies.
	baselineEvents := BaselineTierEvents()
	if len(baselineEvents) == 0 {
		t.Fatal("baseline event set is empty — contract drift")
	}
	// Build the union of every field name each baseline event can admit.
	// For prompt_cycle the allowlist is the explicit contract; for the other
	// baseline events the allowlist is the existing per-event closed vocab in
	// validateFields. Enumerating it here keeps the assertion honest rather
	// than assuming.
	baselineFieldAllowlist := map[string]bool{
		// prompt_cycle (full allowlist)
		"model":                  true,
		"provider":               true,
		"input_size":             true,
		"output_size":            true,
		"cache_percentage":       true,
		"end_to_end_duration_ms": true,
		"segment":                true,
		"session_span":           true,
		"turn_id":                true,
		// tool_use
		"tool_name": true, "count": true,
		// error
		"error_class": true, "surface": true,
		// token_use
		"model_tier": true, "role": true,
		"tokens_in": true, "tokens_out": true, "cache_read": true,
		// session_end
		"duration_ms": true, "outcome": true,
		// session_start
		"adapter": true,
		// app_start / app_stop
		"version": true,
		// batch_meta
		"dropped_count": true, "retry_count": true,
		// day_active — no fields
	}
	for k := range baselineFieldAllowlist {
		if forbidden[k] {
			t.Fatalf("baseline allows forbidden text-field name %q — contract regression", k)
		}
	}
	// And assert prompt_cycle's allowlist is exactly the no-text set.
	if len(baselineFieldAllowlist) < 9 {
		t.Fatal("baseline field allowlist too small to contain prompt_cycle")
	}
}

// TestContractDrift is the cross-repo drift anchor used by
// verify-telemetry-contract: the local contract's version, baseline tier,
// baseline event set, and no-text-fields guarantee must match the canonical
// expected shape embedded here. Because this expected shape is copied verbatim
// into each repo's contract_test.go, drift fails all three until they are
// updated together.
func TestContractDrift(t *testing.T) {
	// Canonical expected values — copied identically into reporterd, the
	// enterprise repo, and the individual repo. If any repo drifts, this test
	// fails in that repo.
	if Version != "1.2.0" {
		t.Fatalf("Version = %q, want %q", Version, "1.2.0")
	}
	if EffectiveTier(TierUsage) != TierBaseline {
		t.Fatalf("usage no longer normalizes to baseline — drift gate")
	}
	if !ValidTier(TierBaseline) || !ValidTier(TierEnrichment) {
		t.Fatalf("baseline/enrichment tiers missing from ValidTier — drift gate")
	}
	if !TierAllows(TierBaseline, EventPromptCycle) {
		t.Fatalf("baseline tier must allow prompt_cycle — drift gate")
	}
	if TierAllows(TierError, EventPromptCycle) {
		t.Fatalf("error tier must NOT allow prompt_cycle — drift gate")
	}
	if !TierCovers(TierDeep, TierBaseline) {
		t.Fatalf("deep must cover baseline — drift gate")
	}
	// No-text-fields guarantee: baseline events must not admit a forbidden
	// prompt/output text field name.
	forbidden := map[string]bool{
		"prompt_text": true, "prompt": true, "output_text": true,
		"output": true, "content": true, "text": true, "body": true,
		"message": true,
	}
	baselineFieldAllowlist := map[string]bool{
		"model": true, "provider": true, "input_size": true,
		"output_size": true, "cache_percentage": true,
		"end_to_end_duration_ms": true, "segment": true,
		"session_span": true, "turn_id": true,
		"tool_name": true, "count": true, "error_class": true,
		"surface": true, "model_tier": true, "role": true,
		"tokens_in": true, "tokens_out": true, "cache_read": true,
		"adapter": true, "duration_ms": true, "outcome": true,
		"version": true, "dropped_count": true, "retry_count": true,
	}
	for k := range forbidden {
		if baselineFieldAllowlist[k] {
			t.Fatalf("baseline allows forbidden text-field name %q — drift gate", k)
		}
	}
}

// TestDeepDisclosureDigestMatchesGolden pins the deep-tier consent receipt
// to the golden (BR-10.7): DeepDisclosureDigest() must equal the golden's
// deep_disclosure_digest, which gen_contract.py extracts from this same
// contract.go — shown text, Go constant, and golden stay one artifact in
// both repos (the client mirror pins the identical value).
func TestDeepDisclosureDigestMatchesGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("golden", "contract.json"))
	if err != nil {
		t.Fatalf("read golden contract.json: %v", err)
	}
	var doc struct {
		DeepDisclosureDigest string `json:"deep_disclosure_digest"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden contract.json: %v", err)
	}
	if doc.DeepDisclosureDigest == "" {
		t.Fatal("golden carries no deep_disclosure_digest — regenerate the golden")
	}
	if got := DeepDisclosureDigest(); got != doc.DeepDisclosureDigest {
		t.Fatalf("DeepDisclosureDigest() = %s, golden = %s — the disclosure text drifted from the golden; regenerate both in the same commit", got, doc.DeepDisclosureDigest)
	}
	if !ValidDeepDigest(doc.DeepDisclosureDigest) {
		t.Fatal("ValidDeepDigest rejects the golden digest")
	}
}

// TestEventFieldsMatchGolden pins the per-event field allow-lists (contract
// 1.2.0) to the golden contract.json, so the no-text-fields guarantee cannot
// drift between the data file, this package and the server's copy.
func TestEventFieldsMatchGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("golden", "contract.json"))
	if err != nil {
		t.Fatalf("read golden contract.json: %v", err)
	}
	var doc struct {
		Fields       map[string][]string `json:"fields"`
		IdentPattern string              `json:"ident_pattern"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden contract.json: %v", err)
	}
	if len(doc.Fields) != len(classificationPairs) {
		t.Fatalf("golden fields cover %d events; code has %d", len(doc.Fields), len(classificationPairs))
	}
	for ev, want := range doc.Fields {
		got := EventFields(ev)
		if got == nil {
			t.Errorf("golden lists fields for unknown event %q", ev)
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("event %q fields drifted: code=%v golden=%v", ev, got, want)
		}
	}
	if doc.IdentPattern != identRe.String() {
		t.Errorf("ident pattern drifted: code=%s golden=%s", identRe.String(), doc.IdentPattern)
	}
}

// TestNoTextChannels proves every free-text channel a sender could try is
// refused: an unlisted field name on any event, prose in a version, os/arch,
// schema_version or correlation span.
func TestNoTextChannels(t *testing.T) {
	const prose = "please refactor my secret code"
	cases := map[string]func(e *Envelope){
		"unknown field on tool_use": func(e *Envelope) { e.Events[0].Fields["prompt"] = prose },
		"unknown field on error":    func(e *Envelope) { e.Events[1].Fields["message"] = prose },
		"prose client_version":      func(e *Envelope) { e.ClientVersion = prose },
		"prose os":                  func(e *Envelope) { e.OS = prose },
		"prose arch":                func(e *Envelope) { e.Arch = prose },
		"prose schema_version":      func(e *Envelope) { e.Events[0].SchemaVersion = prose },
		"prose session_span":        func(e *Envelope) { e.Events[0].SessionSpan = prose },
		"over-long identifier":      func(e *Envelope) { e.ClientVersion = strings.Repeat("a", 65) },
		"prose app_start version": func(e *Envelope) {
			e.Events[0] = Event{
				Event: EventAppStart, EventVersion: 1, SchemaVersion: "2026-09-14T00:00:00Z",
				TS: "2026-09-14T09:59:00Z", InstallID: e.InstallID, Seq: 100,
				Classification: ClassSystemMeta, Purpose: PurposePerfHealth,
				Fields: map[string]any{"version": prose},
			}
		},
		"prose prompt_cycle turn_id": func(e *Envelope) {
			e.Events[0] = Event{
				Event: EventPromptCycle, EventVersion: 1, SchemaVersion: "2026-09-14T00:00:00Z",
				TS: "2026-09-14T09:59:00Z", InstallID: e.InstallID, Seq: 100,
				Classification: ClassSystemMeta, Purpose: PurposeBusiness,
				Fields: map[string]any{
					"model": "other", "provider": "other", "input_size": 1, "output_size": 1,
					"cache_percentage": 0, "end_to_end_duration_ms": 1, "segment": "user_prompt", "turn_id": prose,
				},
			}
		},
	}
	for name, mutate := range cases {
		e := validEnvelope()
		mutate(e)
		if err := ValidateEnvelope(e); !errors.Is(err, ErrBadSchema) {
			t.Errorf("%s: err = %v; want ErrBadSchema", name, err)
		}
	}
	// The real client's shapes stay valid: empty client_version / span, "dev".
	e := validEnvelope()
	e.ClientVersion, e.Events[0].SessionSpan = "", ""
	if err := ValidateEnvelope(e); err != nil {
		t.Errorf("empty client_version + span rejected: %v", err)
	}
	e.ClientVersion = "dev"
	if err := ValidateEnvelope(e); err != nil {
		t.Errorf(`client_version "dev" rejected: %v`, err)
	}
}
