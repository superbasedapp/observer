package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/cloudsessionnet"
	"github.com/marmutapp/superbased-observer/internal/gitview"
)

// cloudsession_state.go holds the flush's small state files (all in
// <observer dir>/cloud-session, mode 0600, no secret and no content) and the
// glue between the flush and two pure tables of internal/cloudsession: the
// coverage record (coverage.go) and the self-modification guard (guard.go).

// cloudSessionCoveragePath is the agent's recorded coverage.
func cloudSessionCoveragePath(stateDir, agent string) string {
	return filepath.Join(stateDir, "coverage-"+agent+".json")
}

// cloudSessionBaselinePath is the agent's recorded hook-block baseline.
func cloudSessionBaselinePath(stateDir, agent string) string {
	return filepath.Join(stateDir, "hook-baseline-"+agent+".json")
}

// readCloudSessionJSON decodes a state file into v. found=false when it is
// missing or unreadable: a corrupt state file is treated as absent, which
// for the baseline means "take a new one from HEAD".
func readCloudSessionJSON(path string, v any) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// writeCloudSessionJSON writes a state file atomically with mode 0600.
func writeCloudSessionJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil { //nolint:gosec // G703: false positive; a file in the flush's own state directory, name built from a fixed prefix and the agent table id
		return err
	}
	return os.Rename(tmp, path)
}

// loadCloudSessionCoverage returns the recorded coverage, nil when none.
func loadCloudSessionCoverage(stateDir, agent string) *cloudsession.Coverage {
	var c cloudsession.Coverage
	if !readCloudSessionJSON(cloudSessionCoveragePath(stateDir, agent), &c) {
		return nil
	}
	return &c
}

// recordCloudSessionCoverage records reason and puts it on the result.
func recordCloudSessionCoverage(stateDir string, res *cloudSessionFlushResult, reason cloudsession.CoverageReason, host, vendorRef string, trig cloudsession.Trigger) {
	c, err := cloudsession.NewCoverage(reason, host, vendorRef, trig, time.Now())
	if err != nil {
		return
	}
	res.Coverage = string(c.State)
	res.CoverageReason = string(c.Reason)
	res.CoverageMessage = c.Message()
	if stateDir != "" {
		_ = writeCloudSessionJSON(cloudSessionCoveragePath(stateDir, res.Agent), c)
	}
}

// deliveryOutcome folds one delivery error into the outcome the coverage
// table classifies.
func deliveryOutcome(o *cloudsession.DeliveryOutcome, derr error) {
	o.Attempted = true
	if derr == nil {
		return
	}
	o.Failed = true
	var de *cloudsessionnet.DeliveryError
	if errors.As(derr, &de) {
		o.NetworkBlocked = de.NetworkBlocked
		o.Status = de.Status
		o.Retryable = de.Retryable
	}
}

// cloudSessionGitShowTimeout bounds the one `git show` the guard runs.
const cloudSessionGitShowTimeout = 5 * time.Second

// cloudSessionHeadFile returns path as committed at root's HEAD. exists is
// false when HEAD does not hold it (or root is not a git repository, or git
// is missing: then nothing committed can be verified, which the guard
// treats exactly like an uncommitted block).
func cloudSessionHeadFile(ctx context.Context, root, path string) (content string, exists bool) {
	if root == "" {
		return "", false
	}
	out, truncated, err := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, cloudSessionGitShowTimeout, "show", "HEAD:"+path)
	if err != nil || truncated {
		return "", false
	}
	return string(out), true
}

// cloudSessionGuard is the guard's outcome for one flush.
type cloudSessionGuard struct {
	Verdict  cloudsession.GuardVerdict
	Reason   cloudsession.CoverageReason
	Baseline cloudsession.HookBaseline
	Current  cloudsession.HookBlock
}

// checkCloudSessionHooks runs the self-modification guard: take (or keep)
// the session's baseline of the owned hook block and compare the working
// tree's block with it.
func checkCloudSessionHooks(ctx context.Context, stateDir, root string, agent cloudsession.Agent, det cloudsession.Detection,
	spec cloudsession.TriggerSpec, trustUncommitted bool,
) (cloudSessionGuard, error) {
	f, ok := cloudsession.HookFile(agent)
	if !ok {
		return cloudSessionGuard{}, fmt.Errorf("%s has no hook file to verify", agent.DisplayName)
	}
	var wt string
	wtExists := false
	if root != "" {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err == nil {
			wt, wtExists = string(b), true
		}
	}
	current, err := cloudsession.OwnedHookBlock(agent, wt, wtExists)
	if err != nil {
		return cloudSessionGuard{}, err
	}
	var prev cloudsession.HookBaseline
	path := cloudSessionBaselinePath(stateDir, agent.ID)
	var prevPtr *cloudsession.HookBaseline
	if readCloudSessionJSON(path, &prev) {
		prevPtr = &prev
	}
	base := prev
	if cloudsession.NeedsBaseline(prevPtr, agent.ID, det.VendorRef, spec) {
		headContent, headExists := cloudSessionHeadFile(ctx, root, f.Path)
		head, err := cloudsession.OwnedHookBlock(agent, headContent, headExists)
		if err != nil {
			return cloudSessionGuard{}, err
		}
		base = cloudsession.PlanBaseline(agent.ID, det.VendorRef, head, current, trustUncommitted)
		// An uncommitted baseline is not kept: committing the hooks and
		// flushing again must be able to establish one.
		if base.Present {
			if err := writeCloudSessionJSON(path, base); err != nil {
				return cloudSessionGuard{}, fmt.Errorf("record hook baseline: %w", err)
			}
		}
	}
	v, reason := cloudsession.CheckHookBlock(base, current)
	return cloudSessionGuard{Verdict: v, Reason: reason, Baseline: base, Current: current}, nil
}
