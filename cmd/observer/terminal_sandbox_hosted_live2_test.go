//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_live2_test.go pins the fixes from the second live
// run of the hosted rows (2026-10-23, at faf43c28a) that are not Linux-only.

// TestHostedLeftoverDeleteSettlesTheLedger (finding F-B: a leftover deleted
// through `observer sandbox hosted delete` kept its whole reservation
// unsettled, and the command printed nothing): the delete settles the
// minutes from the launch to the delete when the record has the start, or
// the planned minutes with a note when it does not, and says what it did.
func TestHostedLeftoverDeleteSettlesTheLedger(t *testing.T) {
	obs, c := hostedLeftoverEnv(t)
	ctx := context.Background()
	now := time.Now()
	for _, run := range []string{"s1", "s2"} {
		info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: run}})
		rec := sandboxremote.NewIntent(run, sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", run, now.Add(-150*time.Second), 10*time.Minute)
		rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
		if run == "s2" {
			rec.CreatedAt = time.Time{}
		}
		if err := hostedSaveRecord(obs, rec); err != nil {
			t.Fatal(err)
		}
		if err := hostedUpdateLedger(obs, now, func(l *sandboxremote.Ledger) error {
			l.Reserve(sandboxremote.VendorE2B, sandboxremote.DayOf(now), run, 10)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	if err := hostedDeleteRun(ctx, obs, "s1", false, &out); err != nil {
		t.Fatal(err)
	}
	if err := hostedDeleteRun(ctx, obs, "s2", false, &out); err != nil {
		t.Fatal(err)
	}
	said := out.String()
	for _, w := range []string{"run s1: deleted the e2b box", "settled 3 box-minutes", "run s2: deleted the e2b box", "settled at the planned 10 box-minutes"} {
		if !strings.Contains(said, w) {
			t.Errorf("output %q lacks %q", said, w)
		}
	}
	var entries []sandboxremote.LedgerEntry
	_ = hostedUpdateLedger(obs, now, func(l *sandboxremote.Ledger) error {
		entries = append(entries, l.Entries...)
		return context.Canceled // read only
	})
	got := map[string]sandboxremote.LedgerEntry{}
	for _, e := range entries {
		got[e.RunID] = e
	}
	if e := got["s1"]; !e.Settled || e.Minutes != 3 || e.Note != "" {
		t.Errorf("s1 %+v", e)
	}
	if e := got["s2"]; !e.Settled || e.Minutes != 10 || e.Note != hostedSettleLeftoverNote {
		t.Errorf("s2 %+v", e)
	}
	if recs := hostedLoadRecords(obs); len(recs) != 0 {
		t.Errorf("records %+v", recs)
	}
}

// TestHostedBoxBinaryLabelSaysUnchecked (finding N3: with box_binary set the
// consent screen named this binary's version for a file it had not
// checked): the label says the file's version is unchecked here and names
// the version the box must report; this binary's own label keeps its
// version.
func TestHostedBoxBinaryLabelSaysUnchecked(t *testing.T) {
	got := hostedBoxBinaryLabel(config.TerminalSandboxHostedProviderConfig{BoxBinary: "/opt/observer-other"})
	if !strings.Contains(got, "/opt/observer-other") || !strings.Contains(got, "unchecked") || strings.HasPrefix(got, "observer "+version) {
		t.Errorf("box_binary label %q", got)
	}
	if self := hostedBoxBinaryLabel(config.TerminalSandboxHostedProviderConfig{}); !strings.HasPrefix(self, "observer "+version) {
		t.Errorf("self label %q", self)
	}
}

// TestSandboxTierRouteNoticeOnNone (finding N2: on the none tier the in-box
// launcher said traffic goes straight to Anthropic): inside a sandbox whose
// tier has no direct route the launcher says the tier's own route; a tier
// with one, or a launch outside a sandbox, keeps the usual notice.
func TestSandboxTierRouteNoticeOnNone(t *testing.T) {
	const proxyURL = "http://127.0.0.1:8820"
	for _, tc := range []struct {
		marker, tier string
		want, not    string
	}{
		{"1", "none", "tier is none", "straight to Anthropic"},
		{"1", "proxy_only", "only route to the model API", "straight to Anthropic"},
		{"1", "internet", "straight to Anthropic", "tier is"},
		{"", "none", "straight to Anthropic", "tier is"},
		{"1", "", "straight to Anthropic", "tier is"},
		{"1", "bogus", "straight to Anthropic", "tier is"},
	} {
		t.Setenv(sandboxEnvMarker, tc.marker)
		t.Setenv(sandbox.EnvEgress, tc.tier)
		got := claudeFallbackNotice(reasonProxyDownClean, proxyURL, "", false, false)
		if !strings.Contains(got, tc.want) || strings.Contains(got, tc.not) {
			t.Errorf("marker %q tier %q: %q", tc.marker, tc.tier, got)
		}
	}
}
