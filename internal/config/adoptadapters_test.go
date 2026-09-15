package config

import (
	"strings"
	"testing"
)

func TestAdoptEnabledAdapters_NoExplicitKey(t *testing.T) {
	body := "[observer]\nlog_level = \"info\"\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.HadExplicitList {
		t.Fatalf("expected HadExplicitList=false, got true")
	}
	if res.Changed {
		t.Fatalf("expected Changed=false, got true")
	}
	if len(res.Missing) != 0 {
		t.Fatalf("expected no missing, got %v", res.Missing)
	}
	if newBody != body {
		t.Fatalf("expected body unchanged\nwant: %q\ngot:  %q", body, newBody)
	}
}

func TestAdoptEnabledAdapters_AlreadyComplete(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.HadExplicitList {
		t.Fatalf("expected HadExplicitList=true")
	}
	if res.Changed {
		t.Fatalf("expected Changed=false, got true")
	}
	if len(res.Missing) != 0 {
		t.Fatalf("expected no missing, got %v", res.Missing)
	}
	if newBody != body {
		t.Fatalf("expected body unchanged\nwant: %q\ngot:  %q", body, newBody)
	}
}

func TestAdoptEnabledAdapters_OneMissing(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	if want := []string{"codex"}; !equalStrs(res.Missing, want) {
		t.Fatalf("Missing = %v, want %v", res.Missing, want)
	}
	want := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_SeveralMissing(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline", "cursor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"codex", "cline", "cursor"}
	if !equalStrs(res.Missing, want) {
		t.Fatalf("Missing = %v, want %v", res.Missing, want)
	}
	wantBody := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\", \"cline\", \"cursor\"]\n"
	if newBody != wantBody {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, wantBody)
	}
}

func TestAdoptEnabledAdapters_NoDuplication(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	_, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "claude-code"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Missing) != 0 {
		t.Fatalf("expected no missing (dup default shouldn't create a gap), got %v", res.Missing)
	}
}

func TestAdoptEnabledAdapters_PreservesOrderAppendsAtEnd(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"cursor\", \"claude-code\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cursor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"codex"}; !equalStrs(res.Missing, want) {
		t.Fatalf("Missing = %v, want %v", res.Missing, want)
	}
	want := "[observer.watch]\nenabled_adapters = [\"cursor\", \"claude-code\", \"codex\"]\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q (operator order must be preserved, new names appended)", newBody, want)
	}
}

func TestAdoptEnabledAdapters_SingleLineArray(t *testing.T) {
	body := `[observer]
log_level = "info"

[observer.watch]
poll_interval_seconds = 2
enabled_adapters = ["claude-code", "codex", "cline"]
`
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline", "cursor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	if !strings.Contains(newBody, `enabled_adapters = ["claude-code", "codex", "cline", "cursor"]`) {
		t.Fatalf("newBody missing expected array line:\n%s", newBody)
	}
	if !strings.Contains(newBody, "poll_interval_seconds = 2") {
		t.Fatalf("unrelated key was lost:\n%s", newBody)
	}
}

func TestAdoptEnabledAdapters_MultiLineArray(t *testing.T) {
	body := `[observer.watch]
enabled_adapters = [
  "claude-code",
  "codex",
]
`
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := `[observer.watch]
enabled_adapters = [
  "claude-code",
  "codex",
  "cline",
]
`
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_MultiLineArray_NoTrailingComma(t *testing.T) {
	body := `[observer.watch]
enabled_adapters = [
  "claude-code",
  "codex"
]
`
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := `[observer.watch]
enabled_adapters = [
  "claude-code",
  "codex",
  "cline",
]
`
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q (missing trailing comma on prior last element must be added)", newBody, want)
	}
}

func TestAdoptEnabledAdapters_InlineCommentsPreserved(t *testing.T) {
	body := "[observer.watch]\n" +
		"enabled_adapters = [\"claude-code\", \"codex\"] # operator pinned list, do not remove entries\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := "[observer.watch]\n" +
		"enabled_adapters = [\"claude-code\", \"codex\", \"cline\"] # operator pinned list, do not remove entries\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_MultiLineTrailingComment(t *testing.T) {
	body := `[observer.watch]
enabled_adapters = [
  "claude-code", # our first adapter
  "codex",
]
`
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex", "cline"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := `[observer.watch]
enabled_adapters = [
  "claude-code", # our first adapter
  "codex",
  "cline",
]
`
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_UnknownExtrasLeftAlone(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"some-future-tool\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"codex"}; !equalStrs(res.Missing, want) {
		t.Fatalf("Missing = %v, want %v", res.Missing, want)
	}
	want := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"some-future-tool\", \"codex\"]\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q (unknown extra name must never be dropped)", newBody, want)
	}
}

func TestAdoptEnabledAdapters_UnsafeValueSkipped(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"variable reference", "[observer.watch]\nenabled_adapters = some_other_key\n"},
		{"non-string element", "[observer.watch]\nenabled_adapters = [\"claude-code\", 42]\n"},
		{"nested array", "[observer.watch]\nenabled_adapters = [[\"claude-code\"], \"codex\"]\n"},
		{"inline table element", "[observer.watch]\nenabled_adapters = [{name = \"claude-code\"}]\n"},
		{"unclosed array", "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newBody, res, err := AdoptEnabledAdapters(tc.body, []string{"claude-code", "codex", "cline"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Skipped {
				t.Fatalf("expected Skipped=true for %q", tc.name)
			}
			if res.SkipReason == "" {
				t.Fatalf("expected non-empty SkipReason")
			}
			if newBody != tc.body {
				t.Fatalf("expected byte-identical body on skip\nwant: %q\ngot:  %q", tc.body, newBody)
			}
			if res.Changed {
				t.Fatalf("Changed must be false on skip")
			}
		})
	}
}

func TestAdoptEnabledAdapters_DottedKeyStyle(t *testing.T) {
	body := "observer.watch.enabled_adapters = [\"claude-code\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := "observer.watch.enabled_adapters = [\"claude-code\", \"codex\"]\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_EmptyArray(t *testing.T) {
	body := "[observer.watch]\nenabled_adapters = []\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	want := "[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	if newBody != want {
		t.Fatalf("newBody =\n%q\nwant:\n%q", newBody, want)
	}
}

func TestAdoptEnabledAdapters_UnrelatedKeyNamedEnabledAdaptersIgnored(t *testing.T) {
	// A same-named key under a DIFFERENT table must not be mistaken for
	// [observer.watch]'s.
	body := "[some.other.table]\nenabled_adapters = [\"not-a-real-one\"]\n\n[observer.watch]\nenabled_adapters = [\"claude-code\"]\n"
	newBody, res, err := AdoptEnabledAdapters(body, []string{"claude-code", "codex"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true")
	}
	if !strings.Contains(newBody, `[some.other.table]`+"\n"+`enabled_adapters = ["not-a-real-one"]`) {
		t.Fatalf("unrelated table's key must be left untouched:\n%s", newBody)
	}
	if !strings.Contains(newBody, `enabled_adapters = ["claude-code", "codex"]`) {
		t.Fatalf("[observer.watch] key not updated:\n%s", newBody)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
