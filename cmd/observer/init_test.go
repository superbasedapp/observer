package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// TestResolveTools_AllReturnsLongTailVendors pins that `observer init
// --all` (and the zero-flag auto-detect default, which resolveTools
// shares the same "requested" accumulation for) actually surfaces
// every one of the seven long-tail prompt-submit-only vendors with no
// dedicated CLI flag — the same list
// TestAutoRegisterRemediation_LongTailVendorsNameNoDedicatedFlag
// (start_test.go) enumerates, kept identical here for consistency.
// Each of these seven is a `PromptLaneHook` registry row with
// Hook.AutoWired=true and a Hook.Mechanism hookSupported's switch
// explicitly recognizes (see internal/integration's registry rows +
// hookSupported in init.go), so autoInitSupported should pass all
// seven today — but this test asserts the RESULT of that live
// three-predicate OR (hookSupported || mcpSupported || routeSupported),
// not a hardcoded assumption, so it would fail loudly (not silently
// pass on a stale list) if a future registry change ever regressed
// one of them out of auto-detection.
func TestResolveTools_AllReturnsLongTailVendors(t *testing.T) {
	longTail := []string{"gemini-cli", "qwen-code", "droid", "qoder", "poolside", "devin", "command-code"}
	installed := append([]string{"claude-code"}, longTail...)

	got := resolveTools(true, false, false, false, false, installed, false)

	for _, tool := range longTail {
		wantSelected := autoInitSupported(tool)
		gotSelected := slices.Contains(got, tool)
		if gotSelected != wantSelected {
			t.Errorf("resolveTools(--all) selected=%v for %q, but autoInitSupported(%q)=%v (registry/predicate mismatch)", gotSelected, tool, tool, wantSelected)
		}
		if !wantSelected {
			t.Errorf("autoInitSupported(%q) = false — this long-tail vendor is no longer auto-detected by --all; if this is an intentional registry change, update this test and the brief that assumed all seven pass", tool)
		}
	}
	if !slices.Contains(got, "claude-code") {
		t.Errorf("resolveTools(--all) = %v, want it to also include claude-code", got)
	}
}

// TestSplitExtensionIDs pins the comma-separated --browser-extension-id
// tokeniser: elements are trimmed, empties dropped, order preserved, and a
// single bare id round-trips to a one-element slice (byte-identical to the
// pre-multi-id behaviour). Dedup + placeholder are the browserhost package's
// job, so this only tokenises.
func TestSplitExtensionIDs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty is nil", in: "", want: nil},
		{name: "whitespace-only is nil", in: "   ", want: nil},
		{name: "single id", in: "abcdefghijklmnopabcdefghijklmnop", want: []string{"abcdefghijklmnopabcdefghijklmnop"}},
		{
			name: "two ids",
			in:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		{
			name: "spaces around elements trimmed",
			in:   " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa , bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ",
			want: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		{
			name: "empty elements dropped",
			in:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,,",
			want: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := splitExtensionIDs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitExtensionIDs(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("element[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestInitBrowserExtensionIDValidation pins that the --browser-extension-id
// flag validates EVERY comma-separated element up front and rejects the whole
// flag naming the offending element — before any file write. Only the
// rejection paths are exercised (a valid id would proceed to real wiring); the
// happy path is covered by the browserhost-level tests.
func TestInitBrowserExtensionIDValidation(t *testing.T) {
	tests := []struct {
		name         string
		flag         string
		wantOffender string
	}{
		{name: "single bad id", flag: "NOT-A-VALID-ID", wantOffender: "NOT-A-VALID-ID"},
		{
			name:         "bad element among valid ones",
			flag:         "abcdefghijklmnopabcdefghijklmnop,NOTVALID",
			wantOffender: "NOTVALID",
		},
		{
			name:         "wrong-length element",
			flag:         "abcdefghijklmnopabcdefghijklmnop,abc",
			wantOffender: "abc",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newInitCmd()
			cmd.SetArgs([]string{"--browser-extension-id", tc.flag})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected an error for flag %q, got nil", tc.flag)
			}
			if !strings.Contains(err.Error(), tc.wantOffender) {
				t.Errorf("error %q should name the offending element %q", err.Error(), tc.wantOffender)
			}
			if !strings.Contains(err.Error(), "browser-extension-id") {
				t.Errorf("error %q should reference the flag name", err.Error())
			}
		})
	}
}

// TestResolveBrowserExtensionIDFlag pins the FINDING 1 fix directly against
// the pure helper (no cobra plumbing, no risk of the RunE falling through
// into real wiring): a value that tokenizes to zero ids is REJECTED when the
// flag was explicitly supplied (changed=true), but tolerated when the flag
// was never passed (changed=false) — that's the placeholder / interactive-
// prompt case, unchanged from before the fix. A valid multi-id value
// normalizes and round-trips regardless of changed.
func TestResolveBrowserExtensionIDFlag(t *testing.T) {
	const idA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const idB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tests := []struct {
		name    string
		changed bool
		raw     string
		want    string
		wantErr bool
	}{
		{
			name:    "valid multi-id, flag changed",
			changed: true,
			raw:     idA + "," + idB,
			want:    idA + "," + idB,
		},
		{
			name:    "valid multi-id, flag not changed (defensive — shouldn't happen in practice)",
			changed: false,
			raw:     idA + "," + idB,
			want:    idA + "," + idB,
		},
		{
			name:    "supplied but tokenizes to zero ids — commas and whitespace only — is rejected",
			changed: true,
			raw:     ", ,",
			wantErr: true,
		},
		{
			name:    "supplied as pure whitespace is rejected",
			changed: true,
			raw:     "   ",
			wantErr: true,
		},
		{
			name:    "supplied as empty string is rejected",
			changed: true,
			raw:     "",
			wantErr: true,
		},
		{
			name:    "flag not supplied at all — empty string tolerated (placeholder path)",
			changed: false,
			raw:     "",
			want:    "",
		},
		{
			name:    "flag not supplied at all — zero-token garbage tolerated too (defensive)",
			changed: false,
			raw:     ", ,",
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBrowserExtensionIDFlag(tc.changed, tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveBrowserExtensionIDFlag(%v, %q) = %q, nil; want an error", tc.changed, tc.raw, got)
				}
				if !strings.Contains(err.Error(), "browser-extension-id") {
					t.Errorf("error %q should reference the flag name", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveBrowserExtensionIDFlag(%v, %q): unexpected error: %v", tc.changed, tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("resolveBrowserExtensionIDFlag(%v, %q) = %q, want %q", tc.changed, tc.raw, got, tc.want)
			}
		})
	}
}

// TestInitBrowserExtensionIDZeroTokenRejectionViaCLI exercises the fix
// through the actual cobra flag-parsing seam (cmd.Flags().Changed), not just
// the pure helper — pinning that --browser-extension-id ", ," (FINDING 1's
// reproduction) is rejected end to end BEFORE any wiring is attempted, and
// that omitting the flag entirely still reaches the classic (non-browser-
// only) init path without tripping the new rejection. Only the rejection /
// non-rejection outcome is asserted here — a real accepted value would
// proceed into runBrowserOnlyInit's real filesystem detection, which
// TestResolveBrowserExtensionIDFlag already covers without that risk.
func TestInitBrowserExtensionIDZeroTokenRejectionViaCLI(t *testing.T) {
	t.Run("supplied but zero ids after tokenizing is rejected", func(t *testing.T) {
		cmd := newInitCmd()
		cmd.SetArgs([]string{"--browser-extension-id", ", ,"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("expected rejection for --browser-extension-id %q, got nil (output:\n%s)", ", ,", out.String())
		}
		if !strings.Contains(err.Error(), "browser-extension-id") {
			t.Errorf("error %q should reference the flag name", err.Error())
		}
		if !strings.Contains(err.Error(), "no usable extension id") {
			t.Errorf("error %q should explain the zero-token reason", err.Error())
		}
	})

	t.Run("flag not supplied never triggers the zero-token rejection", func(t *testing.T) {
		cmd := newInitCmd()
		cmd.SetArgs([]string{"--dry-run"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		err := cmd.Execute()
		if err != nil && strings.Contains(err.Error(), "browser-extension-id") {
			t.Fatalf("flag not supplied should never trigger the browser-extension-id rejection, got: %v", err)
		}
	})
}
