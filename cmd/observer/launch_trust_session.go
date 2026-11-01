//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_trust_session.go is the session-start flag of the repository
// trust component (security pillar plan section 5.1, "Trigger and
// enforcement": the session-start hook flags the same verdict for tools
// launched outside Observer). After a session-start hook has replied, it
// runs the trust check where the session started and records each
// untrusted or flagged reason nobody accepted as a repo_trust finding
// (scope prelaunch), and prints one line on the hook's stderr. It never
// blocks: the session has already started, and the launch row is where
// Observer can refuse.

// sessionStartTrustBudget bounds the whole flag (config, database, check).
const sessionStartTrustBudget = 2 * time.Second

// recordSessionStartTrust is the flag for one session-start hook body. It
// does nothing unless security.trust is selected and the guard is on (the
// same switch as the launch row, newRepoTrustDeps), and is best effort.
func recordSessionStartTrust(ctx context.Context, tool string, body []byte, configPath string, stderr io.Writer) {
	p, ok := decodeObservePayload(body)
	if !ok || strings.TrimSpace(p.Cwd) == "" {
		return
	}
	if !repoTrustSelected(componentSnapshotFor(configPath)) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, sessionStartTrustBudget)
	defer cancel()
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	if !repoTrustGuardOn(cfg) {
		return
	}
	n, out, err := flagSessionStartTrustWith(ctx, store.New(database), tool, p.Cwd, os.Getenv(repoTrustCheckedEnv), repoTrustLocalStep(cfg.Security.Trust), time.Now())
	if err != nil || out.result.Verdict == sectrust.VerdictClean || stderr == nil {
		return
	}
	fmt.Fprintln(stderr, sessionStartTrustLine(out, n, out.launched))
}

// repoTrustGuardOn reports whether the guard is enabled with a mode other
// than off: the trust row and the session flag run only then.
func repoTrustGuardOn(cfg config.Config) bool {
	if !cfg.Guard.Enabled {
		return false
	}
	mode, err := policy.ParseMode(modeOrDefaultGuard(cfg.Guard.Mode))
	return err == nil && mode != policy.ModeOff
}

// sessionStartTrustLine is the one line the flag prints on the hook's
// stderr. A session Observer launched had its launch checked (and asked or
// warned there), so the line says so instead of calling it unchecked.
func sessionStartTrustLine(out repoTrustOutcome, n int, launched bool) string {
	codes := strings.Join(verdictReasonCodes(out.result), ", ")
	if out.floorRaised && out.verdict.Decision >= policy.DecisionAsk {
		// The org's pre-launch trust floor raised the step (lane SEC-P4
		// decision 9): a session already started cannot be refused, so the
		// line says what a launch here would have met. Only when the floor
		// caused the verdict (audit SEC-P4 F8): an ask or refusal a local
		// rule or override gave is not the org's.
		codes += "; the org's pre-launch trust floor for this project " + map[bool]string{true: "refuses", false: "asks before"}[out.verdict.Decision == policy.DecisionDeny] + " a launch here"
	} else if out.localRaised && out.verdict.Decision >= policy.DecisionAsk {
		// The node's own [security.trust] prelaunch = ask raised it (audit
		// LEFT-SEC F5): the line says what a launch here would have met.
		codes += "; your [security.trust] prelaunch setting asks before a launch here"
	}
	if launched {
		return fmt.Sprintf("observer: repository trust: %s is %s (%s), as its launch check reported; %d finding(s) recorded; review and accept in the dashboard's New Terminal dialog or with `observer security trust check` there",
			out.target.root, out.result.Verdict, codes, n)
	}
	return fmt.Sprintf("observer: repository trust: this session started outside Observer, so its launch was not checked; %s is %s (%s); %d finding(s) recorded; review and accept in the dashboard's New Terminal dialog or with `observer security trust check` there",
		out.target.root, out.result.Verdict, codes, n)
}

// flagSessionStartTrust runs the check at dir and records one finding per
// reason at flagged level or above that is not accepted. checkedRoot is the
// launch marker (repoTrustCheckedEnv): when it names the session's own
// repository, Observer launched the session and checked it at launch, and
// the findings say so. It returns how many findings it recorded.
func flagSessionStartTrust(ctx context.Context, st *store.Store, tool, dir, checkedRoot string, now time.Time) (int, repoTrustOutcome, error) {
	return flagSessionStartTrustWith(ctx, st, tool, dir, checkedRoot, "", now)
}

// flagSessionStartTrustWith is flagSessionStartTrust with the node's own
// [security.trust] prelaunch step (repoTrustLocalStep), applied as the
// launch path applies it (lane LEFT-SEC audit F5): before the org floor,
// raise only.
func flagSessionStartTrustWith(ctx context.Context, st *store.Store, tool, dir, checkedRoot, localStep string, now time.Time) (int, repoTrustOutcome, error) {
	out, err := evaluateRepoTrust(ctx, &repoTrustDeps{mode: policy.ModeObserve, store: st, trustFloor: repoTrustFloorReader(daemonConfigPath()), localStep: localStep}, tool, dir)
	if err != nil {
		return 0, out, err
	}
	rootHash := guard.HashProjectRoot(out.target.root)
	out.launched = checkedRoot != "" && checkedRoot == rootHash
	n := 0
	for _, r := range out.result.Reasons {
		if r.Level < sectrust.LevelFlagged || r.Accepted {
			continue
		}
		if _, _, err := st.UpsertSecFinding(ctx, sessionStartTrustFinding(rootHash, tool, r, out.launched, now), now); err != nil {
			return n, out, err
		}
		n++
	}
	return n, out, nil
}

// sessionStartTrustFinding is the repo_trust finding of one reason. The
// message comes from the reason-code table, never from repository text.
func sessionStartTrustFinding(rootHash, tool string, r sectrust.Reason, launched bool, now time.Time) secfinding.Finding {
	rule := "repo-trust/" + r.Code
	sev := policy.FindingSeverityMedium
	if r.Level == sectrust.LevelUntrusted {
		sev = policy.FindingSeverityHigh
	}
	what := r.Code
	for _, row := range sectrust.Codes() {
		if row.Code == r.Code {
			what = row.Input
		}
	}
	f := secfinding.Finding{
		Rule:       secfinding.Rule{ID: rule, Version: "1", Pack: repoTrustComponent, PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: "sectrust"},
		Category:   policy.FindingRepoTrust,
		Severity:   sev,
		Confidence: policy.FindingConfidenceHigh,
		Scope:      policy.FindingScopePrelaunch,
		Project:    secfinding.Project{RootHash: rootHash},
		Location:   secfinding.Location{RelPath: r.File},
		Message:    sessionStartTrustWho(launched) + " in a repository the trust check reports as " + r.Level.String() + ": " + what + ".",
		FixHint:    "Review it in the dashboard's New Terminal dialog for the project, or run `observer security trust check` there; accept a repository command only after reading it.",
		Lineage:    secfinding.Lineage{Tool: tool},
		FirstSeen:  now,
		LastSeen:   now,
	}
	f.LocalKey = secfinding.LocalKey(rootHash, rule, secfinding.TextIdentity(r.File+"\x00"+r.Key+"\x00"+r.Digest))
	return secfinding.Normalize(f)
}

// sessionStartTrustWho opens a session-start finding's message.
func sessionStartTrustWho(launched bool) string {
	if launched {
		return "A session Observer launched (its launch check ran and the launch went on)"
	}
	return "A session started outside Observer (its launch was not checked)"
}
