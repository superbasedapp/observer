package hook_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestClearedRefusalStillReported pins T-887 (guard tamper re-test
// 2026-10-17 case 2): a managed pass refuses a foreign artifact, the
// developer puts things right before the next ACCEPTED report (the org was
// unreachable), and the next pass succeeds. The refusal must still reach the
// organization: the registry keeps the failure time past the "ok", and the
// probe reports hook_registration_failed carrying it for a day.
func TestClearedRefusalStillReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tamper environment uses POSIX executables")
	}
	for _, target := range sortedOwnedTargets() {
		t.Run(target, func(t *testing.T) {
			src := newTamperEnvWith(t, true)
			first, canonical, ok := src.installed(t, target)
			if !ok {
				t.Skipf("writer wrote nothing on this host: err=%v skipped=%v", first.Error, first.Skipped)
			}
			foreign, ok := neutraliseArtifact(canonical, first.ConfigPath, src.binary)
			if !ok {
				t.Fatalf("neutralise did not apply to %s", first.ConfigPath)
			}
			e := newTamperEnvWith(t, true)
			path := strings.Replace(first.ConfigPath, src.home, e.home, 1)
			foreign = bytes.ReplaceAll(foreign, []byte(src.home), []byte(e.home))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, foreign, 0o600); err != nil {
				t.Fatal(err)
			}
			refusedAt := time.Date(2026, 10, 17, 18, 3, 40, 0, time.UTC)
			if rec := e.reg.Reconcile(target, e.tracker, refusedAt); rec.Result.Error == nil {
				t.Fatal("the foreign artifact was not refused")
			}
			sig := e.inspect(target, refusedAt)
			if _, ok := locatedRisk(sig, target, orgcontract.CaptureRiskHookRegistrationError); !ok {
				t.Fatal("refusal not reported as hook_registration_error")
			}
			if _, ok := locatedRisk(sig, target, orgcontract.CaptureRiskHookRegistrationFailed); ok {
				t.Fatal("a refusal that still holds was also reported as cleared")
			}

			// The developer removes the foreign file; the next pass installs.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			okAt := refusedAt.Add(5 * time.Minute)
			if rec := e.reg.Reconcile(target, e.tracker, okAt); rec.Result.Error != nil {
				t.Fatalf("the pass after the fix failed: %v", rec.Result.Error)
			}
			sig = e.inspect(target, okAt.Add(70*time.Minute))
			if it, ok := locatedRisk(sig, target, orgcontract.CaptureRiskHookRegistrationError); ok {
				t.Fatalf("the cleared error is still standing: %+v", it)
			}
			it, ok := locatedRisk(sig, target, orgcontract.CaptureRiskHookRegistrationFailed)
			if !ok {
				t.Fatalf("the cleared refusal left no trace: %+v", sig.Items)
			}
			if it.At != refusedAt.Format(time.RFC3339) {
				t.Fatalf("hook_registration_failed At = %q, want the refusal time %s", it.At, refusedAt.Format(time.RFC3339))
			}

			// A day later the record has aged out.
			if _, ok := locatedRisk(e.inspect(target, refusedAt.Add(25*time.Hour)), target, orgcontract.CaptureRiskHookRegistrationFailed); ok {
				t.Fatal("hook_registration_failed outlived its window")
			}
		})
	}
}
