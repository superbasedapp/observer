package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// TestNodeInterventionSourceResolve pins the 2026-09-15 ruling at the decision
// boundary, class and reason together: a running process is stopped only on a
// MEASURED crossing or a STRUCTURALLY unavailable accounting source. A capture
// pass that merely could not finish the newest tail - because the governed
// tool is writing the very files it reads - is delayed, stays ready, and
// denies nothing.
//
// Class and reason come from ONE ordered table, so this also pins that the
// reason always names the precondition the class was taken from. In
// particular, a stale capture result must not launder a source whose own
// recorded reason is structural: the adapter is still unknown, the allow list
// still excludes it, the file is still unreadable.
func TestNodeInterventionSourceResolve(t *testing.T) {
	t.Parallel()
	ready := watcher.BudgetCaptureStatus{Ready: true, Reason: watcher.BudgetCaptureReasonReady}
	status := func(reason string) watcher.BudgetCaptureStatus {
		return watcher.BudgetCaptureStatus{Reason: reason}
	}
	for _, tc := range []struct {
		name        string
		sane        bool
		nativeUsage bool
		source      watcher.BudgetCaptureStatus
		wantClass   watcher.BudgetAccountingClass
		wantReason  string
	}{
		// Structural before everything else: no native usage means nothing on
		// this node can read that surface's spend.
		{"surface has no native usage", true, false, ready, watcher.BudgetAccountingUnavailable, "native_usage_unavailable"},
		{"surface has no native usage and no capture result", false, false, ready, watcher.BudgetAccountingUnavailable, "native_usage_unavailable"},

		// A stale or absent strict result is a stale TAIL, not unknown spend.
		{"no usable capture result", false, true, ready, watcher.BudgetAccountingDelayed, "capture_result_unavailable"},
		{"no capture pass ran at all", false, true, watcher.BudgetCaptureStatus{}, watcher.BudgetAccountingDelayed, "capture_result_unavailable"},
		// ...but it never upgrades a recorded structural source to delayed.
		{"no usable capture result over a broken source", false, true, status(watcher.BudgetCaptureReasonUnknownAdapter), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonUnknownAdapter},
		{"no usable capture result over an unreadable source", false, true, status(watcher.BudgetCaptureReasonUnreadable), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonUnreadable},
		// A stale result over a merely delayed source stays delayed.
		{"no usable capture result over a delayed source", false, true, status(watcher.BudgetCaptureReasonRetrySuggested), watcher.BudgetAccountingDelayed, "capture_result_unavailable"},

		{"known: ready", true, true, ready, watcher.BudgetAccountingKnown, watcher.BudgetCaptureReasonReady},
		{"known: missing root", true, true, status(watcher.BudgetCaptureReasonMissingRoot), watcher.BudgetAccountingKnown, watcher.BudgetCaptureReasonMissingRoot},
		{"known: no source files", true, true, status(watcher.BudgetCaptureReasonNoFiles), watcher.BudgetAccountingKnown, watcher.BudgetCaptureReasonNoFiles},
		{"known: no source evidence", true, true, status(watcher.BudgetCaptureReasonNoEvidence), watcher.BudgetAccountingKnown, watcher.BudgetCaptureReasonNoEvidence},
		{"known: warnings", true, true, status(watcher.BudgetCaptureReasonWarnings), watcher.BudgetAccountingKnown, watcher.BudgetCaptureReasonWarnings},

		{"delayed: retry suggested", true, true, status(watcher.BudgetCaptureReasonRetrySuggested), watcher.BudgetAccountingDelayed, watcher.BudgetCaptureReasonRetrySuggested},
		{"delayed: scan incomplete", true, true, status(watcher.BudgetCaptureReasonIncomplete), watcher.BudgetAccountingDelayed, watcher.BudgetCaptureReasonIncomplete},
		{"delayed: scan canceled", true, true, status(watcher.BudgetCaptureReasonCanceled), watcher.BudgetAccountingDelayed, watcher.BudgetCaptureReasonCanceled},
		{"delayed: parse error", true, true, status(watcher.BudgetCaptureReasonParseError), watcher.BudgetAccountingDelayed, watcher.BudgetCaptureReasonParseError},
		{"delayed: parser panic", true, true, status(watcher.BudgetCaptureReasonParserPanic), watcher.BudgetAccountingDelayed, watcher.BudgetCaptureReasonParserPanic},

		{"structural: unknown adapter", true, true, status(watcher.BudgetCaptureReasonUnknownAdapter), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonUnknownAdapter},
		{"structural: allow filtered", true, true, status(watcher.BudgetCaptureReasonAllowFiltered), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonAllowFiltered},
		{"structural: store unavailable", true, true, status(watcher.BudgetCaptureReasonStoreUnavailable), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonStoreUnavailable},
		{"structural: oversize file", true, true, status(watcher.BudgetCaptureReasonOversizeFile), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonOversizeFile},
		{"structural: unsafe symlink", true, true, status(watcher.BudgetCaptureReasonUnsafeSymlink), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonUnsafeSymlink},
		{"structural: source unreadable", true, true, status(watcher.BudgetCaptureReasonUnreadable), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonUnreadable},
		{"structural: no required sources", true, true, status(watcher.BudgetCaptureReasonNoRequiredSources), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonNoRequiredSources},
		{"structural: no capture status", true, true, status(watcher.BudgetCaptureReasonMissingStatus), watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonMissingStatus},
		// Fail closed on a reason nobody has classified, and on a status no
		// pass ever produced.
		{"structural: unclassified reason", true, true, status("brand_new_failure"), watcher.BudgetAccountingUnavailable, "brand_new_failure"},
		{"structural: zero status", true, true, watcher.BudgetCaptureStatus{}, watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonMissingStatus},
		// A whole-pass class outranks the one reason chosen for the operator.
		{
			"structural: class outranks a delayed reason",
			true, true,
			watcher.BudgetCaptureStatus{Reason: watcher.BudgetCaptureReasonIncomplete, Class: watcher.BudgetAccountingUnavailable},
			watcher.BudgetAccountingUnavailable, watcher.BudgetCaptureReasonIncomplete,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, reason := nodeInterventionSourceResolve(tc.sane, tc.nativeUsage, tc.source)
			if class != tc.wantClass {
				t.Fatalf("class = %q, want %q", class, tc.wantClass)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
			got := nodeInterventionResolveSource("muse", tc.sane, tc.nativeUsage, tc.source)
			if got.Tool != "muse" || got.Reason != tc.wantReason {
				t.Fatalf("resolved source = %+v, want the same reason", got)
			}
			if got.Ready != (tc.wantClass != watcher.BudgetAccountingUnavailable) {
				t.Fatalf("resolved source = %+v, want ready only outside the unavailable class", got)
			}
			if got.Delayed != (tc.wantClass == watcher.BudgetAccountingDelayed) {
				t.Fatalf("resolved source = %+v, want delayed only inside the delayed class", got)
			}
			if got.Delayed && !got.Ready {
				t.Fatalf("a delayed source denied its own tool: %+v", got)
			}
		})
	}
}
