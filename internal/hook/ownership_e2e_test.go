package hook_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// T-872 end to end, per mechanism that owns its artifact by name. The
// registry-driven gate (TestEveryHookMechanismReportsAndRepairsTamper,
// "neutralise" / "neutralise-managed") pins repaired-on-managed and
// refused-on-individual for every target; these pin the rest of the
// contract: the repair keeps the old bytes recoverable and names its rule,
// and a FOREIGN artifact in Observer's slot (Observer never installed it)
// is refused and reported even on a managed node.

func sortedOwnedTargets() []string {
	out := make([]string, 0, len(ownedByNameTargets))
	for t := range ownedByNameTargets {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// TestManagedRepairOfNeutralisedOwnedArtifact: neutralise, one managed pass,
// then the artifact is canonical, the repair is classified and reported with
// the owned-neutralised rule, and a non-credential artifact's pre-repair bytes
// sit in a displaced copy (T-884: <path>.displaced-<UTC>, mode 0600, named on
// the hook_repaired item), never at <path>.bak.
func TestManagedRepairOfNeutralisedOwnedArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tamper environment uses POSIX executables")
	}
	for _, target := range sortedOwnedTargets() {
		t.Run(target, func(t *testing.T) {
			e := newTamperEnvWith(t, true)
			first, canonical, ok := e.installed(t, target)
			if !ok {
				t.Skipf("writer wrote nothing on this host: err=%v skipped=%v", first.Error, first.Skipped)
			}
			path := first.ConfigPath
			neutral, ok := neutraliseArtifact(canonical, path, e.binary)
			if !ok {
				t.Fatalf("neutralise did not apply to %s", path)
			}
			if err := os.WriteFile(path, neutral, 0o600); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			rec := e.reg.Reconcile(target, e.tracker, now)
			if rec.Result.Error != nil || len(rec.Repaired) == 0 {
				t.Fatalf("not repaired: err=%v repaired=%v", rec.Result.Error, rec.Repaired)
			}
			if p := e.reg.Probe(target); p.Error != nil || len(hook.DriftEvents(p)) != 0 {
				t.Fatalf("artifact not canonical after the repair: err=%v drift=%v", p.Error, hook.DriftEvents(p))
			}
			ruled := false
			for _, rw := range rec.Result.Rewrites {
				if rw.Rule == "owned-neutralised" {
					ruled = true
				}
			}
			if !ruled {
				t.Fatalf("repair did not name the owned-neutralised rule: %+v", rec.Result.Rewrites)
			}
			item, ok := locatedRisk(e.inspect(target, now), target, orgcontract.CaptureRiskHookRepaired)
			if !ok {
				t.Fatal("repair not reported as hook_repaired with tool and file")
			}
			if _, err := os.Stat(path + ".bak"); err == nil {
				t.Fatal("the repair wrote <path>.bak; it keeps a displaced copy instead (T-884)")
			}
			copies := fsatomic.DisplacedCopies(path)
			if integration.HooksShareCredentialFile(target) {
				if len(copies) != 0 || rec.Result.RepairCopy != "" || item.KeptCopy != "" {
					t.Fatalf("a credential-bearing file was copied: %v %q %q", copies, rec.Result.RepairCopy, item.KeptCopy)
				}
				return
			}
			if len(copies) != 1 || copies[0] != rec.Result.RepairCopy {
				t.Fatalf("displaced copies = %v, result names %q", copies, rec.Result.RepairCopy)
			}
			if kept, err := os.ReadFile(copies[0]); err != nil || !bytes.Equal(kept, neutral) {
				t.Fatalf("pre-repair bytes not kept at %s: err=%v", copies[0], err)
			}
			if info, err := os.Stat(copies[0]); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("copy mode = %v (%v), want 0600", info.Mode().Perm(), err)
			}
			if want := diag.RiskFileLabel(e.home, copies[0]); item.KeptCopy != want || !orgcontract.ValidRiskFileLabel(item.KeptCopy) {
				t.Fatalf("hook_repaired kept_copy = %q, want %q", item.KeptCopy, want)
			}
		})
	}
}

// TestManagedRepairCopiesNeverOverwriteAndAreCapped pins T-884 per owned
// mechanism: a user's own <path>.bak survives a repair untouched, repeated
// repairs each keep a new copy, and at most hook.RepairCopiesKept copies of
// one artifact remain (the newest), each reported path being one that exists.
func TestManagedRepairCopiesNeverOverwriteAndAreCapped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tamper environment uses POSIX executables")
	}
	for _, target := range sortedOwnedTargets() {
		t.Run(target, func(t *testing.T) {
			if integration.HooksShareCredentialFile(target) {
				t.Skip("a credential-bearing file is never copied")
			}
			e := newTamperEnvWith(t, true)
			first, canonical, ok := e.installed(t, target)
			if !ok {
				t.Skipf("writer wrote nothing on this host: err=%v skipped=%v", first.Error, first.Skipped)
			}
			path := first.ConfigPath
			userBak := []byte("the developer's own backup\n")
			if err := os.WriteFile(path+".bak", userBak, 0o644); err != nil {
				t.Fatal(err)
			}
			neutral, ok := neutraliseArtifact(canonical, path, e.binary)
			if !ok {
				t.Fatalf("neutralise did not apply to %s", path)
			}
			var reported []string
			for i := 0; i < hook.RepairCopiesKept+2; i++ {
				if err := os.WriteFile(path, neutral, 0o600); err != nil {
					t.Fatal(err)
				}
				rec := e.reg.Reconcile(target, e.tracker, time.Now())
				if rec.Result.Error != nil || len(rec.Repaired) == 0 || rec.Result.RepairCopy == "" {
					t.Fatalf("pass %d: err=%v repaired=%v copy=%q", i, rec.Result.Error, rec.Repaired, rec.Result.RepairCopy)
				}
				reported = append(reported, rec.Result.RepairCopy)
				if item, ok := locatedRisk(e.inspect(target, time.Now()), target, orgcontract.CaptureRiskHookRepaired); !ok ||
					item.KeptCopy != diag.RiskFileLabel(e.home, rec.Result.RepairCopy) {
					t.Fatalf("pass %d: hook_repaired item %+v does not name %s", i, item, rec.Result.RepairCopy)
				}
			}
			if got, _ := os.ReadFile(path + ".bak"); !bytes.Equal(got, userBak) {
				t.Fatalf("the user's own .bak was changed: %q", got)
			}
			copies := fsatomic.DisplacedCopies(path)
			want := reported[len(reported)-hook.RepairCopiesKept:]
			if len(copies) != hook.RepairCopiesKept || strings.Join(copies, "\n") != strings.Join(want, "\n") {
				t.Fatalf("copies = %q, want the newest %d %q", copies, hook.RepairCopiesKept, want)
			}
		})
	}
}

// TestManagedRepairRefusesForeignArtifactInOwnedSlot: content Observer never
// installed (no hook_checksums.json record) at Observer's own path or under
// Observer's own entry name is the developer's, so a managed pass refuses it,
// leaves it byte-identical and reports it.
func TestManagedRepairRefusesForeignArtifactInOwnedSlot(t *testing.T) {
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
			now := time.Now()
			rec := e.reg.Reconcile(target, e.tracker, now)
			if rec.Result.Error == nil {
				t.Fatalf("a foreign artifact in Observer's slot was taken over: added=%v rewrites=%+v", rec.Result.HooksAdded, rec.Result.Rewrites)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, foreign) {
				t.Fatalf("foreign artifact modified:\n%s", got)
			}
			if _, err := os.Stat(path + ".bak"); err == nil {
				t.Fatal("a refused registration wrote a backup")
			}
			if copies := fsatomic.DisplacedCopies(path); len(copies) != 0 {
				t.Fatalf("a refused registration kept a displaced copy: %v", copies)
			}
			if _, ok := locatedRisk(e.inspect(target, now), target, orgcontract.CaptureRiskHookRegistrationError); !ok {
				t.Fatal("refusal not reported as hook_registration_error with tool and file")
			}
		})
	}
}

// TestManagedRepairKeepsRefusingContentOnlyArtifacts: an entry that is
// Observer's only by its command (an event list in the vendor's own settings
// file) cannot be told from the developer's own hook once neutralised, so a
// managed pass still refuses it.
func TestManagedRepairKeepsRefusingContentOnlyArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the tamper environment uses POSIX executables")
	}
	for _, target := range []string{"cursor", "codex", "gemini-cli", "devin"} {
		t.Run(target, func(t *testing.T) {
			e := newTamperEnvWith(t, true)
			first, canonical, ok := e.installed(t, target)
			if !ok {
				t.Skipf("writer wrote nothing on this host: err=%v skipped=%v", first.Error, first.Skipped)
			}
			neutral, ok := neutraliseArtifact(canonical, first.ConfigPath, e.binary)
			if !ok {
				t.Fatalf("neutralise did not apply to %s", first.ConfigPath)
			}
			if err := os.WriteFile(first.ConfigPath, neutral, 0o600); err != nil {
				t.Fatal(err)
			}
			rec := e.reg.Reconcile(target, e.tracker, time.Now())
			if rec.Result.Error == nil {
				t.Fatalf("a content-only artifact was rewritten on a managed pass: added=%v", rec.Result.HooksAdded)
			}
			if got, _ := os.ReadFile(first.ConfigPath); !bytes.Equal(got, neutral) {
				t.Fatal("refused artifact modified")
			}
		})
	}
}
