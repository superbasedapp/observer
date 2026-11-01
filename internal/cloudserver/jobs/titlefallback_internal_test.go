package jobs

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/tagtaxonomy"
)

// TestFallbackTitle walks the fallback ladder (T-967): description first
// sentence, then tag labels, then the neutral title. Nothing is invented.
func TestFallbackTitle(t *testing.T) {
	slugs := tagtaxonomy.Slugs()
	if len(slugs) < 4 {
		t.Fatalf("the tag vocabulary has %d slugs; this test needs 4", len(slugs))
	}
	label := func(slug string) string {
		tag, _ := tagtaxonomy.Lookup(slug)
		return tag.Label
	}
	cases := []struct {
		name string
		r    cloudcontract.Result
		want string
	}{
		{
			"first sentence of the description",
			cloudcontract.Result{Description: "Reworked the retry loop in the proxy. Tests pass."},
			"Reworked the retry loop in the proxy",
		},
		{
			"whitespace collapsed",
			cloudcontract.Result{Description: "  Added   a\n device exchange!  Then more."},
			"Added a device exchange",
		},
		{
			"long description cut at a word boundary",
			cloudcontract.Result{Description: strings.Repeat("word ", 40)},
			strings.TrimSpace(strings.Repeat("word ", 16)),
		},
		{
			"no description: tag labels in order, at most three, unknown slugs skipped",
			cloudcontract.Result{TaxonomyTags: []string{slugs[0], "not-a-tag", slugs[1], slugs[2], slugs[3]}},
			strings.Join([]string{label(slugs[0]), label(slugs[1]), label(slugs[2])}, ", "),
		},
		{
			"nothing usable",
			cloudcontract.Result{Description: "   ", TaxonomyTags: []string{"not-a-tag"}},
			untitledSessionTitle,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fallbackTitle(tc.r)
			if got != tc.want {
				t.Fatalf("fallbackTitle = %q, want %q", got, tc.want)
			}
			if len([]rune(got)) > fallbackTitleMaxRunes {
				t.Fatalf("fallback %q exceeds %d runes", got, fallbackTitleMaxRunes)
			}
		})
	}
}

// TestProcessLunaCompletionTitleFallback pins that an empty title no longer
// fails validation (the paid retry seen live on 2026-10-23), that the repair is
// reported, and that every other field keeps its validation.
func TestProcessLunaCompletionTitleFallback(t *testing.T) {
	body := func(title, desc, confidence string) string {
		b, _ := json.Marshal(map[string]any{
			"title": title, "description": desc, "confidence": confidence,
			"taxonomy_tags": []string{}, "suggested_tags": []string{},
			"evidence_refs": []string{}, "limitations": []string{},
		})
		return string(b)
	}
	cases := []struct {
		name         string
		content      string
		wantTitle    string
		wantFallback bool
		wantReject   string
	}{
		{"model title kept", body("Proxy retry rework", "Reworked it.", "low"), "Proxy retry rework", false, ""},
		{"empty title repaired from the description", body("", "Reworked the retry loop. Done.", "low"), "Reworked the retry loop", true, ""},
		{"blank title repaired", body("   ", "", "low"), untitledSessionTitle, true, ""},
		{"other fields still validated", body("", "d", "SUPER"), "", true, "validate:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nr, notes, rejection := ProcessLunaCompletionNoted(tc.content, map[string]struct{}{})
			if notes.TitleFallback != tc.wantFallback {
				t.Fatalf("TitleFallback = %v, want %v", notes.TitleFallback, tc.wantFallback)
			}
			if tc.wantReject != "" {
				if !strings.HasPrefix(rejection, tc.wantReject) {
					t.Fatalf("rejection = %q, want prefix %q", rejection, tc.wantReject)
				}
				return
			}
			if rejection != "" {
				t.Fatalf("unexpected rejection %q", rejection)
			}
			if nr.Title.String() != tc.wantTitle {
				t.Fatalf("title = %q, want %q", nr.Title.String(), tc.wantTitle)
			}
			// The plain entry point runs the same pipeline.
			plain, rej := ProcessLunaCompletion(tc.content, map[string]struct{}{})
			if rej != "" || plain.Title.String() != tc.wantTitle {
				t.Fatalf("ProcessLunaCompletion = (%q, %q)", plain.Title.String(), rej)
			}
		})
	}
}

// TestLunaPromptRequiresATitle pins the strengthened instruction.
func TestLunaPromptRequiresATitle(t *testing.T) {
	if !strings.Contains(lunaSystemPrompt, "title: REQUIRED and never empty") {
		t.Fatal("the system prompt no longer states that the title is required")
	}
}

// TestJobOutcomeAttrs pins the per-job log line (T-968): identifiers, counters
// and the state only, with the job id cut to its prefix.
func TestJobOutcomeAttrs(t *testing.T) {
	run := jobRun{
		jobID: "ed03880a-6a13-46fc-80e6-ec548cc9b2a4", feature: "session_enrichment",
		routeID: "session_enrichment.haiku.v4", attempts: 2, tokensIn: 33686, tokensOut: 784, titleFallback: true,
	}
	cases := []struct {
		name string
		out  Outcome
		err  error
		want []any
	}{
		{"succeeded", Outcome{JobID: run.jobID, State: "succeeded"}, nil, []any{
			"job", "ed03880a", "feature", "session_enrichment", "route_id", "session_enrichment.haiku.v4",
			"attempts", 2, "state", "succeeded", "reason", "", "tokens_in", int64(33686),
			"tokens_out", int64(784), "title_fallback", true,
		}},
		{"failed carries the reason", Outcome{JobID: run.jobID, State: "failed", Reason: "provider_invalid_output"}, nil, []any{
			"job", "ed03880a", "feature", "session_enrichment", "route_id", "session_enrichment.haiku.v4",
			"attempts", 2, "state", "failed", "reason", "provider_invalid_output", "tokens_in", int64(33686),
			"tokens_out", int64(784), "title_fallback", true,
		}},
		{"an error is state error", Outcome{}, errors.New("record attempt: boom"), []any{
			"job", "ed03880a", "feature", "session_enrichment", "route_id", "session_enrichment.haiku.v4",
			"attempts", 2, "state", "error", "reason", "", "tokens_in", int64(33686),
			"tokens_out", int64(784), "title_fallback", true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobOutcomeAttrs(run, tc.out, tc.err); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("jobOutcomeAttrs = %v, want %v", got, tc.want)
			}
		})
	}
}
