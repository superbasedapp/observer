package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLifecycleNote pins the doctor's lifecycle note: active is StatusOK and
// reads lowercase, both non-active statuses are StatusWarn (NEVER Fail — a
// sunset product still captures, so nothing is broken) and are SHOUTED, and
// the grounded note is appended VERBATIM rather than paraphrased.
func TestLifecycleNote(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lifecycle  integration.Lifecycle
		note       string
		wantStatus Status
		wantSubstr []string
	}{
		{"active without a note", integration.LifecycleActive, "", StatusOK, []string{"lifecycle: active"}},
		{
			"active with an alias caveat",
			integration.LifecycleActive, "answers to the deprecated name \"windsurf\"",
			StatusOK,
			[]string{"lifecycle: active", "answers to the deprecated name"},
		},
		{
			"deprecated",
			integration.LifecycleDeprecated, "renamed 2026-06-02; https://example.invalid/rename",
			StatusWarn,
			[]string{"lifecycle: DEPRECATED", "renamed 2026-06-02", "https://example.invalid/rename"},
		},
		{
			"dead",
			integration.LifecycleDead, "shut down 2026-04-21; https://example.invalid/eol",
			StatusWarn,
			[]string{"lifecycle: DEAD", "shut down 2026-04-21"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, line := lifecycleNote(tc.lifecycle, tc.note)
			if status != tc.wantStatus {
				t.Errorf("status = %v, want %v", status, tc.wantStatus)
			}
			if status == StatusFail {
				t.Error("a lifecycle note must never be a FAIL — capture keeps running for a sunset product")
			}
			for _, want := range tc.wantSubstr {
				if !strings.Contains(line, want) {
					t.Errorf("note %q does not contain %q", line, want)
				}
			}
		})
	}
}

// TestCheckAdapterCarriesALifecycleNote pins that every per-adapter doctor
// check reports the row's harness lifecycle. claude-code is active with no
// note; cline is active but carries the Roo Code retag caveat, which must
// print verbatim.
func TestCheckAdapterCarriesALifecycleNote(t *testing.T) {
	for _, tool := range []string{"claude-code", "cline"} {
		c, ok := CheckAdapter(tool, config.Config{})
		if !ok {
			t.Fatalf("CheckAdapter(%q) ok = false", tool)
		}
		var found string
		for _, d := range c.Details {
			if strings.HasPrefix(d, "lifecycle: ") {
				found = d
			}
		}
		if found == "" {
			t.Fatalf("CheckAdapter(%q) has no lifecycle note: %v", tool, c.Details)
		}
		if !strings.Contains(found, "active") {
			t.Errorf("CheckAdapter(%q) lifecycle note = %q, want active", tool, found)
		}
	}
	c, _ := CheckAdapter("cline", config.Config{})
	joined := strings.Join(c.Details, "\n")
	if !strings.Contains(joined, "roo-code") {
		t.Errorf("cline's lifecycle note does not carry the Roo Code retag caveat verbatim:\n%s", joined)
	}
}

// TestCheckAdapterAnswersRowlessProducts pins the `observer doctor roo-code`
// path: a product with no adapter and no registry row, but a lifecycle entry,
// gets a real Check instead of falling through to the substring filter (which
// would tell an operator Observer never heard of a tool whose data it is
// actively parsing). The single note carries the lifecycle + grounded note
// verbatim; the message names the servicing adapter.
func TestCheckAdapterAnswersRowlessProducts(t *testing.T) {
	c, ok := CheckAdapter("roo-code", config.Config{})
	if !ok {
		t.Fatal("CheckAdapter(\"roo-code\") ok = false — the rowless product path did not fire")
	}
	if c.Name != "roo-code" {
		t.Errorf("Check.Name = %q, want roo-code", c.Name)
	}
	if c.Status != StatusWarn {
		t.Errorf("Check.Status = %v, want StatusWarn (dead is a warning, never a failure)", c.Status)
	}
	if !strings.Contains(c.Message, "roo-code is dead") {
		t.Errorf("Check.Message = %q, want it to say roo-code is dead", c.Message)
	}
	if !strings.Contains(c.Message, "serviced by cline") {
		t.Errorf("Check.Message = %q, want it to name the servicing adapter", c.Message)
	}
	if len(c.Details) != 1 {
		t.Fatalf("Check.Details = %v, want exactly one lifecycle note", c.Details)
	}
	_, note, _ := integration.LifecycleFor("roo-code")
	if !strings.Contains(c.Details[0], note) {
		t.Errorf("Check.Details[0] does not carry the registry note verbatim:\n got %q\nwant %q", c.Details[0], note)
	}
	if !strings.HasPrefix(c.Details[0], "lifecycle: DEAD") {
		t.Errorf("Check.Details[0] = %q, want a `lifecycle: DEAD` prefix", c.Details[0])
	}
}

// TestCheckAdapterAdapterlessProductNamesNoAdapter pins the "" Adapter
// rendering: a dead product nothing reads must say so plainly rather than
// implying some parser covers it.
func TestCheckAdapterAdapterlessProductNamesNoAdapter(t *testing.T) {
	c, ok := CheckAdapter("open-interpreter-python", config.Config{})
	if !ok {
		t.Fatal("CheckAdapter(\"open-interpreter-python\") ok = false")
	}
	if !strings.Contains(c.Message, "no adapter") {
		t.Errorf("Check.Message = %q, want it to say no adapter services the product", c.Message)
	}
}

// TestCheckAdapterUnknownIDStillFallsThrough pins that the rowless-product
// path did NOT widen CheckAdapter's contract: an id neither the adapter list
// nor the lifecycle policy knows still returns ok=false, so the caller's
// substring filter over the general checks keeps working.
func TestCheckAdapterUnknownIDStillFallsThrough(t *testing.T) {
	for _, id := range []string{"definitely-not-a-tool", "org", ""} {
		if _, ok := CheckAdapter(id, config.Config{}); ok {
			t.Errorf("CheckAdapter(%q) ok = true, want false (must fall through to the check filter)", id)
		}
	}
}
