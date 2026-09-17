//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestBudgetLaunchAccountingSourceIsPerTool pins the per-TOOL rule at the
// launch boundary: one adapter's broken accounting source denies THAT
// adapter's launches and leaves every other adapter's alone. It is the same
// rule the node's process controller applies to a running process, read from
// the report that controller leaves behind.
func TestBudgetLaunchAccountingSourceIsPerTool(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		unready  string
		tool     string
		wantErr  error
		wantRule string
	}{
		{
			name: "this tool's source is unavailable", unready: "claude-code", tool: "claude-code",
			wantErr: errBudgetLaunchDenied, wantRule: "B-623",
		},
		{name: "another tool's source is unavailable", unready: "opencode", tool: "claude-code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			writeBudgetLaunchCaptureStatus(t, dbPath, tc.unready)
			err := enforceBudgetControlledLaunch(ctx, cfgPath, tc.tool, budgetLaunchEvidence{
				Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820",
			})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("launch refused for ANOTHER tool's broken source: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), tc.wantRule) {
				t.Fatalf("admission error = %v, want %v naming %s", err, tc.wantErr, tc.wantRule)
			}
			if !strings.Contains(err.Error(), tc.tool) {
				t.Fatalf("rendered error %q does not name the tool whose source failed", err.Error())
			}
		})
	}
}

// TestBudgetLaunchAccountingSourceDefaultsReadyWithoutAReport keeps the
// default honest: a tool the report does not mention had no governed process
// to catch up, and an absent/unverifiable report is the same answer. The
// report is context, never the authority.
func TestBudgetLaunchAccountingSourceDefaultsReadyWithoutAReport(t *testing.T) {
	ctx := context.Background()
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	if got := budgetLaunchAccountingSource(ctx, st, dbPath, "claude-code"); !got.Ready {
		t.Fatalf("no controller report at all = %+v, want ready", got)
	}
	writeBudgetLaunchCaptureStatus(t, dbPath, "opencode")
	if got := budgetLaunchAccountingSource(ctx, st, dbPath, "claude-code"); !got.Ready {
		t.Fatalf("unreported tool = %+v, want ready", got)
	}
	got := budgetLaunchAccountingSource(ctx, st, dbPath, "opencode")
	if got.Ready || got.Reason == "" {
		t.Fatalf("reported-unready tool = %+v, want an unready answer with a reason", got)
	}
}

// writeBudgetLaunchCaptureStatus leaves a live, verifiable controller report
// whose capture map reports exactly one tool's accounting source as broken.
func writeBudgetLaunchCaptureStatus(t *testing.T, dbPath, unreadyTool string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	controller, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nodeInterventionAuthority(ctx, st, controller.UID, time.Now().UTC())
	if err != nil || !authority.Authorized {
		t.Fatalf("authority = %+v, err=%v", authority, err)
	}
	if err := writeNodeInterventionStatus(ctx, dbPath, nodeInterventionStatus{
		At: time.Now().UTC(), Controller: controller, Authority: authority.Authority,
		State: "partial", ProcessCutoff: "active",
		ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		Reason: "verified installed processes only",
		Capture: map[string]nodeInterventionCaptureStatus{
			unreadyTool: {Ready: false, Reason: "capture_result_unavailable"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}
