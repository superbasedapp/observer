package watcher

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// TestBudgetCaptureReadinessClassifiesEveryReason pins the closed
// classification table. It reads the reason constants out of the source rather
// than from a hand-maintained list, so a new BudgetCaptureReason* constant
// fails here until somebody decides whether it means "this tool's spend is
// measured", "the tail is merely late" or "this tool's spend cannot be read on
// this node". An unclassified reason is unavailable at runtime, but silently
// defaulting is exactly the decision the arc that produced this table was made
// to stop.
//
// The delayed column is the 2026-09-15 ruling: the strict pass is a tail
// accelerator, not the source of truth for the total, so a transient tail
// failure against a file the governed tool is actively writing must never stop
// that tool.
func TestBudgetCaptureReadinessClassifiesEveryReason(t *testing.T) {
	t.Parallel()
	want := map[string]BudgetAccountingClass{
		BudgetCaptureReasonReady:             BudgetAccountingKnown,
		BudgetCaptureReasonMissingRoot:       BudgetAccountingKnown,
		BudgetCaptureReasonNoFiles:           BudgetAccountingKnown,
		BudgetCaptureReasonNoEvidence:        BudgetAccountingKnown,
		BudgetCaptureReasonWarnings:          BudgetAccountingKnown,
		BudgetCaptureReasonParseError:        BudgetAccountingDelayed,
		BudgetCaptureReasonParserPanic:       BudgetAccountingDelayed,
		BudgetCaptureReasonRetrySuggested:    BudgetAccountingDelayed,
		BudgetCaptureReasonCanceled:          BudgetAccountingDelayed,
		BudgetCaptureReasonIncomplete:        BudgetAccountingDelayed,
		BudgetCaptureReasonUnreadable:        BudgetAccountingUnavailable,
		BudgetCaptureReasonOversizeFile:      BudgetAccountingUnavailable,
		BudgetCaptureReasonUnsafeSymlink:     BudgetAccountingUnavailable,
		BudgetCaptureReasonUnknownAdapter:    BudgetAccountingUnavailable,
		BudgetCaptureReasonAllowFiltered:     BudgetAccountingUnavailable,
		BudgetCaptureReasonStoreUnavailable:  BudgetAccountingUnavailable,
		BudgetCaptureReasonNoRequiredSources: BudgetAccountingUnavailable,
		BudgetCaptureReasonMissingStatus:     BudgetAccountingUnavailable,
	}

	declared := budgetCaptureReasonConstants(t)
	if len(declared) == 0 {
		t.Fatal("no BudgetCaptureReason constants were found in the source")
	}
	for name, value := range declared {
		row, ok := budgetCaptureReadinessFor(value)
		if !ok {
			t.Errorf("%s (%q) has no row in budgetCaptureReadinessTable", name, value)
			continue
		}
		if row.note == "" {
			t.Errorf("%s (%q) has no classification note", name, value)
		}
		expected, listed := want[value]
		if !listed {
			t.Errorf("%s (%q) is not covered by this test's expectations", name, value)
			continue
		}
		if row.class != expected {
			t.Errorf("%s (%q) class = %q, want %q", name, value, row.class, expected)
		}
		status := BudgetCaptureStatus{Reason: value}
		if got := status.AccountingClass(); got != expected {
			t.Errorf("%s (%q) AccountingClass = %q, want %q", name, value, got, expected)
		}
		wantReady := expected != BudgetAccountingUnavailable
		if got := status.AccountingReady(); got != wantReady {
			t.Errorf("%s (%q) AccountingReady = %v, want %v", name, value, got, wantReady)
		}
		wantDelayed := expected == BudgetAccountingDelayed
		if got := status.AccountingDelayed(); got != wantDelayed {
			t.Errorf("%s (%q) AccountingDelayed = %v, want %v", name, value, got, wantDelayed)
		}
		if status.AccountingReason() != value {
			t.Errorf("%s AccountingReason = %q, want %q", name, status.AccountingReason(), value)
		}
	}
	for _, row := range budgetCaptureReadinessTable {
		if _, ok := want[row.reason]; !ok {
			t.Errorf("table row %q classifies a reason this test does not expect", row.reason)
		}
	}
	if len(budgetCaptureReadinessTable) != len(want) {
		t.Errorf("table has %d rows, expectations have %d", len(budgetCaptureReadinessTable), len(want))
	}
}

// TestBudgetCaptureReadinessRejectsUnknownAndZeroStatus pins the fail-closed
// edges: a status the pass never produced, and a reason nobody classified. It
// also pins the delayed edge, which is ready without being known.
func TestBudgetCaptureReadinessRejectsUnknownAndZeroStatus(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		status      BudgetCaptureStatus
		wantClass   BudgetAccountingClass
		wantReady   bool
		wantDelayed bool
		wantReason  string
	}{
		{"zero status", BudgetCaptureStatus{}, BudgetAccountingUnavailable, false, false, BudgetCaptureReasonMissingStatus},
		{"ready flag without a classified reason", BudgetCaptureStatus{Ready: true}, BudgetAccountingUnavailable, false, false, BudgetCaptureReasonMissingStatus},
		{"unclassified reason", BudgetCaptureStatus{Reason: "brand_new_failure"}, BudgetAccountingUnavailable, false, false, "brand_new_failure"},
		{"classified ready reason", BudgetCaptureStatus{Reason: BudgetCaptureReasonMissingRoot}, BudgetAccountingKnown, true, false, BudgetCaptureReasonMissingRoot},
		// Ruling 2026-09-15: a deferred tail is late, not unknown. It stays
		// ready - the measured total in the store decides - and reports itself
		// as delayed so an operator can see why the newest spend is missing.
		{"delayed reason", BudgetCaptureStatus{Reason: BudgetCaptureReasonRetrySuggested}, BudgetAccountingDelayed, true, true, BudgetCaptureReasonRetrySuggested},
		// The pass's own Class answers for every issue it produced; Reason
		// names only the one an operator reads, and the structural reasons
		// rank last in that choice.
		{
			"stored class outranks a benign reason",
			BudgetCaptureStatus{Reason: BudgetCaptureReasonIncomplete, Class: BudgetAccountingUnavailable},
			BudgetAccountingUnavailable, false, false, BudgetCaptureReasonIncomplete,
		},
		{
			"stored delayed class on a reason that reads as known",
			BudgetCaptureStatus{Reason: BudgetCaptureReasonWarnings, Class: BudgetAccountingDelayed},
			BudgetAccountingDelayed, true, true, BudgetCaptureReasonWarnings,
		},
		// A class value this build does not know is not a licence to run.
		{
			"unknown class value",
			BudgetCaptureStatus{Reason: BudgetCaptureReasonReady, Class: BudgetAccountingClass("brand_new_class")},
			BudgetAccountingUnavailable, false, false, BudgetCaptureReasonReady,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.status.AccountingClass(); got != tc.wantClass {
				t.Errorf("AccountingClass = %q, want %q", got, tc.wantClass)
			}
			if got := tc.status.AccountingReady(); got != tc.wantReady {
				t.Errorf("AccountingReady = %v, want %v", got, tc.wantReady)
			}
			if got := tc.status.AccountingDelayed(); got != tc.wantDelayed {
				t.Errorf("AccountingDelayed = %v, want %v", got, tc.wantDelayed)
			}
			if got := tc.status.AccountingReason(); got != tc.wantReason {
				t.Errorf("AccountingReason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

// budgetCaptureReasonConstants reads the declared reason constants out of the
// package source so the coverage check cannot drift from the code.
func budgetCaptureReasonConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "budgetcapture.go", nil, 0)
	if err != nil {
		t.Fatalf("parse budgetcapture.go: %v", err)
	}
	out := make(map[string]string)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if len(name.Name) < len("BudgetCaptureReason") || name.Name[:len("BudgetCaptureReason")] != "BudgetCaptureReason" {
					continue
				}
				if i >= len(value.Values) {
					t.Fatalf("%s has no literal value", name.Name)
				}
				lit, ok := value.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				out[name.Name] = unquoted
			}
		}
	}
	return out
}
