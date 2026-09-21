package guard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// P0-7 guard hot-reload tests (§7.1/§7.4). They drive ReloadOrgLayer
// through the SAME parse/verify path New uses and prove: a successful
// reload swaps the running org version + hash and makes a v2-only rule
// fire (§7.1); a bad bundle is a fail-safe no-op (§7.1); a reload is
// race-safe against a concurrent Evaluate storm (§3.4, the crux gate);
// and the per-snapshot project-engine cache is dropped + rebuilt
// against the new org layer (§7.1).

// orgSigner returns a signer bound to ONE key pair, so v1/v2/v3 bundles
// all verify against a single enrolment pin (unlike bundle_test's
// signedEnvelope, which mints a fresh key per call). The returned pin
// is what enrolment would have recorded (orgcontract.PublicKeyPinHash).
func orgSigner(t *testing.T) (sign func(version int64, bundleTOML string) string, pin string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sign = func(version int64, bundleTOML string) string {
		b := orgcontract.PolicyBundle{
			Version:    version,
			BundleTOML: bundleTOML,
			Signature:  orgcontract.SignPolicyBundle(priv, version, []byte(bundleTOML)),
			PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
			SignedAt:   "2026-06-11T09:00:00Z",
		}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal envelope: %v", err)
		}
		return string(raw)
	}
	return sign, orgcontract.PublicKeyPinHash(pub)
}

// orgRuleTOML is a one-rule org bundle whose rule ID + command marker
// are unique per version, so "the v2 rule fires and the v1 rule does
// not" is an unambiguous swap signal.
func orgRuleTOML(id, marker string) string {
	return fmt.Sprintf(`
[[rule]]
id = %q
category = "exfil"
severity = "high"
decision = "ask"
applies_to = ["shell_exec"]
match.command_regex = %q
`, id, marker)
}

// shellEvent builds a shell_exec probe event carrying command as its
// target (what match.command_regex matches against).
func shellEvent(command, projectRoot string) policy.Event {
	return policy.Event{
		Kind:        policy.KindShellExec,
		ActionType:  "run_command",
		Target:      command,
		ProjectRoot: projectRoot,
	}
}

// orgStateOf returns the loaded org-layer PolicyState (ok=false when no
// org layer is loaded).
func orgStateOf(g *Guard) (PolicyState, bool) {
	for _, st := range g.PolicyStates() {
		if st.Layer == layerOrg {
			return st, true
		}
	}
	return PolicyState{}, false
}

// firedRuleID evaluates command and returns the matched rule ID ("" when
// nothing matched).
func firedRuleID(g *Guard, command, projectRoot string) string {
	v, _ := g.Evaluate(shellEvent(command, projectRoot))
	return v.RuleID
}

// TestGuardReloadOrgLayer_SwapsRunningVersionAndHash (§7.1): a live
// reload from v1 to v2 flips PolicyStates()' org entry to the new
// version + hash, and a v2-only rule now fires while the v1-only rule
// no longer does. Mutation-ready: neutering g.set.Store(newES) leaves
// the state at v1 → the version + firing assertions fail.
func TestGuardReloadOrgLayer_SwapsRunningVersionAndHash(t *testing.T) {
	t.Parallel()
	sign, pin := orgSigner(t)
	files := map[string]string{orgBundlePath: sign(1, orgRuleTOML("ORG-V1", "onlyv1"))}
	g := orgGuard(t, files, pin)

	v1, ok := orgStateOf(g)
	if !ok || v1.Version != "1" {
		t.Fatalf("initial org state = %+v (ok=%v), want version 1", v1, ok)
	}
	if got := firedRuleID(g, "echo onlyv1", "/home/u/proj"); got != "ORG-V1" {
		t.Fatalf("pre-reload onlyv1 fired %q, want ORG-V1", got)
	}
	if got := firedRuleID(g, "echo onlyv2", "/home/u/proj"); got == "ORG-V2" {
		t.Fatalf("pre-reload onlyv2 already fired ORG-V2 (v2 not yet loaded)")
	}

	// Publish v2 to the cache path and reload live.
	files[orgBundlePath] = sign(2, orgRuleTOML("ORG-V2", "onlyv2"))
	if err := g.ReloadOrgLayer(context.Background()); err != nil {
		t.Fatalf("ReloadOrgLayer: %v", err)
	}

	v2, ok := orgStateOf(g)
	if !ok || v2.Version != "2" {
		t.Fatalf("post-reload org state = %+v (ok=%v), want version 2", v2, ok)
	}
	if v2.ContentHash == v1.ContentHash {
		t.Fatalf("content hash did not change on reload (%q)", v2.ContentHash)
	}
	if got := firedRuleID(g, "echo onlyv2", "/home/u/proj"); got != "ORG-V2" {
		t.Fatalf("post-reload onlyv2 fired %q, want ORG-V2 (new layer not live)", got)
	}
	if got := firedRuleID(g, "echo onlyv1", "/home/u/proj"); got == "ORG-V1" {
		t.Fatalf("post-reload onlyv1 still fired ORG-V1 (old layer not swapped out)")
	}
}

// TestGuardReloadOrgLayer_VersionOnlyBumpConverges pins P0-7 BLOCKER 1:
// an identical-content version bump (server bumps version, BundleTOML
// unchanged) MUST publish so the running version converges to the
// cached version. Short-circuiting on content-hash alone would leave
// running=v1 / cached=v2 → P0-6 pending_restart forever.
func TestGuardReloadOrgLayer_VersionOnlyBumpConverges(t *testing.T) {
	t.Parallel()
	sign, pin := orgSigner(t)
	toml := orgRuleTOML("ORG-SAME", "samecmd")
	files := map[string]string{orgBundlePath: sign(1, toml)}
	g := orgGuard(t, files, pin)

	v1, ok := orgStateOf(g)
	if !ok || v1.Version != "1" {
		t.Fatalf("initial org state = %+v (ok=%v), want version 1", v1, ok)
	}

	// Same TOML, version 2 — the exact identical-content bump.
	files[orgBundlePath] = sign(2, toml)
	if err := g.ReloadOrgLayer(context.Background()); err != nil {
		t.Fatalf("ReloadOrgLayer(version-only bump): %v", err)
	}

	v2, ok := orgStateOf(g)
	if !ok || v2.Version != "2" {
		t.Fatalf("post-bump org state = %+v (ok=%v), want version 2 (hash-only no-op would leave v1)", v2, ok)
	}
	if v2.ContentHash != v1.ContentHash {
		t.Fatalf("content hash changed on identical-content bump: v1=%q v2=%q", v1.ContentHash, v2.ContentHash)
	}
	// A second reload of the same v2 is the true no-op (hash AND version).
	if err := g.ReloadOrgLayer(context.Background()); err != nil {
		t.Fatalf("ReloadOrgLayer(idempotent v2): %v", err)
	}
	v2b, ok := orgStateOf(g)
	if !ok || !reflect.DeepEqual(v2b, v2) {
		t.Fatalf("idempotent reload mutated state: before=%+v after=%+v (ok=%v)", v2, v2b, ok)
	}
}

// TestGuardReloadOrgLayer_BadBundleIsNoOp (§7.1): every failed-verify
// bundle makes ReloadOrgLayer return an error and leave the running org
// state exactly as it was (fail-safe — a bad reload never downgrades
// the live policy).
func TestGuardReloadOrgLayer_BadBundleIsNoOp(t *testing.T) {
	t.Parallel()
	sign, pin := orgSigner(t)
	otherSign, _ := orgSigner(t) // a different signing key → pin mismatch

	// A well-formed v2 the same key signs, then corrupted three ways.
	goodV2 := sign(2, orgRuleTOML("ORG-V2", "onlyv2"))
	var env orgcontract.PolicyBundle
	if err := json.Unmarshal([]byte(goodV2), &env); err != nil {
		t.Fatalf("unmarshal good v2: %v", err)
	}
	tampered := env
	tampered.BundleTOML += "# tampered\n" // body no longer matches the signature
	tamperedRaw, _ := json.Marshal(tampered)

	cases := []struct {
		name string
		body string
	}{
		{"garbage json", "{not json"},
		{"tampered toml breaks signature", string(tamperedRaw)},
		{"pin mismatch (different key)", otherSign(2, orgRuleTOML("ORG-V2", "onlyv2"))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]string{orgBundlePath: sign(1, orgRuleTOML("ORG-V1", "onlyv1"))}
			g := orgGuard(t, files, pin)
			before, ok := orgStateOf(g)
			if !ok {
				t.Fatalf("v1 org state not loaded")
			}

			files[orgBundlePath] = tc.body
			if err := g.ReloadOrgLayer(context.Background()); err == nil {
				t.Fatalf("ReloadOrgLayer accepted a bad bundle (want error)")
			}

			after, ok := orgStateOf(g)
			if !ok || !reflect.DeepEqual(after, before) {
				t.Fatalf("org state changed on failed reload: before=%+v after=%+v (ok=%v)", before, after, ok)
			}
			// The v1 rule must still be live; the v2 rule must not.
			if got := firedRuleID(g, "echo onlyv1", "/home/u/proj"); got != "ORG-V1" {
				t.Fatalf("v1 rule not live after failed reload: fired %q", got)
			}
			if got := firedRuleID(g, "echo onlyv2", "/home/u/proj"); got == "ORG-V2" {
				t.Fatalf("bad bundle leaked ORG-V2 into the live engine")
			}
		})
	}
}

// TestGuardReloadOrgLayer_DropsProjectEngineCache (§7.1): a project
// engine warmed against v1 must, after a reload to v2, rebuild against
// the new org layer — a v2-only rule fires through the PROJECT-scoped
// path (the per-snapshot project cache was dropped with the base).
func TestGuardReloadOrgLayer_DropsProjectEngineCache(t *testing.T) {
	t.Parallel()
	sign, pin := orgSigner(t)
	projPolicy := "[[rule]]\nid = \"PROJ-1\"\ncategory = \"exfil\"\nseverity = \"high\"\ndecision = \"flag\"\napplies_to = [\"shell_exec\"]\nmatch.command_regex = 'projmarker'\n"
	files := map[string]string{
		orgBundlePath: sign(1, orgRuleTOML("ORG-V1", "onlyv1")),
		"/home/u/proj/.observer/guard-policy.toml": projPolicy,
	}
	g := orgGuard(t, files, pin)

	// Warm the project engine: a project-scoped eval builds + caches a
	// merged (org v1 + project) engine for /home/u/proj.
	if got := firedRuleID(g, "echo projmarker", "/home/u/proj"); got != "PROJ-1" {
		t.Fatalf("project rule not live pre-reload: fired %q", got)
	}
	if got := firedRuleID(g, "echo onlyv1", "/home/u/proj"); got != "ORG-V1" {
		t.Fatalf("org v1 rule not live through the project engine: fired %q", got)
	}
	if got := firedRuleID(g, "echo onlyv2", "/home/u/proj"); got == "ORG-V2" {
		t.Fatalf("v2 rule fired before reload")
	}

	files[orgBundlePath] = sign(2, orgRuleTOML("ORG-V2", "onlyv2"))
	if err := g.ReloadOrgLayer(context.Background()); err != nil {
		t.Fatalf("ReloadOrgLayer: %v", err)
	}

	// The warm v1 project engine must be gone: the project-scoped eval
	// rebuilds against org v2 and the v2-only rule now fires.
	if got := firedRuleID(g, "echo onlyv2", "/home/u/proj"); got != "ORG-V2" {
		t.Fatalf("project cache not dropped: onlyv2 fired %q, want ORG-V2", got)
	}
	if got := firedRuleID(g, "echo onlyv1", "/home/u/proj"); got == "ORG-V1" {
		t.Fatalf("stale v1 project engine still live: onlyv1 fired ORG-V1")
	}
	// The project layer itself survives the org reload (it re-merges).
	if got := firedRuleID(g, "echo projmarker", "/home/u/proj"); got != "PROJ-1" {
		t.Fatalf("project rule lost after reload: fired %q", got)
	}
}

// syncFS is a concurrency-safe ReadFile backing for the race test: the
// reload goroutines swap the bundle bytes under a lock while New/reload
// read them, so any race the detector reports is in the guard, never in
// the test harness.
type syncFS struct {
	mu sync.RWMutex
	m  map[string][]byte
}

func newSyncFS() *syncFS { return &syncFS{m: make(map[string][]byte)} }

func (f *syncFS) read(path string) ([]byte, error) {
	key := strings.ReplaceAll(path, "\\", "/")
	f.mu.RLock()
	defer f.mu.RUnlock()
	if b, ok := f.m[key]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, os.ErrNotExist
}

func (f *syncFS) set(path string, body []byte) {
	key := strings.ReplaceAll(path, "\\", "/")
	f.mu.Lock()
	f.m[key] = append([]byte(nil), body...)
	f.mu.Unlock()
}

// TestGuardReloadOrgLayer_ConcurrentWithEvaluate (§3.4, the crux -race
// gate): N goroutines hammer Evaluate (rootless AND project-scoped, to
// exercise es.base AND es.projectEngines) plus Mode/RuleCount/
// EffectiveRules/PolicyStates/CategoryFor, while M goroutines publish a
// monotonically increasing org version and call ReloadOrgLayer. Under
// -race this MUST fail if any lock-free org-derived read escapes the
// engineSet snapshot. After the storm the running org version equals
// the last successfully-loaded one.
func TestGuardReloadOrgLayer_ConcurrentWithEvaluate(t *testing.T) {
	t.Parallel()
	const n = 150
	sign, pin := orgSigner(t)

	envelopes := make([][]byte, n)
	for i := 0; i < n; i++ {
		v := int64(i + 1)
		envelopes[i] = []byte(sign(v, orgRuleTOML(fmt.Sprintf("ORG-V%d", v), fmt.Sprintf("onlyv%d", v))))
	}

	fs := newSyncFS()
	fs.set(orgBundlePath, envelopes[0]) // v1 is live at construction
	g, err := New(Options{
		Config:            guardCfgOrg(),
		Home:              "/home/u",
		KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile:          fs.read,
		OrgKeyPinHash:     pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}

	var next int64 // hand out strictly increasing versions across reloaders
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Readers: hammer every lock-free org-derived surface.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				g.Evaluate(shellEvent("echo onlyv1", ""))             // es.base
				g.Evaluate(shellEvent("echo onlyv2", "/home/u/proj")) // es.projectEngines
				_ = g.Mode()
				_ = g.RuleCount()
				_ = g.EffectiveRules()
				_ = g.PolicyStates()
				_ = g.CategoryFor("R-110")
			}
		}()
	}

	// Writers: publish increasing versions until the pool is exhausted.
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func(seed int64) {
			defer writers.Done()
			r := mrand.New(mrand.NewSource(seed))
			for {
				idx := atomic.AddInt64(&next, 1)
				if idx >= int64(n) {
					return
				}
				fs.set(orgBundlePath, envelopes[idx])
				_ = g.ReloadOrgLayer(context.Background())
				if r.Intn(8) == 0 {
					_ = g.PolicyStates() // occasional writer-side read
				}
			}
		}(int64(i) + 1)
	}
	writers.Wait()
	close(done)
	wg.Wait()

	// Deterministic settle: publish the highest version and reload once
	// so the final running state is well-defined regardless of the
	// concurrent interleaving above.
	top := int64(n)
	fs.set(orgBundlePath, envelopes[n-1])
	if err := g.ReloadOrgLayer(context.Background()); err != nil {
		t.Fatalf("final settle reload: %v", err)
	}
	st, ok := orgStateOf(g)
	if !ok || st.Version != fmt.Sprintf("%d", top) {
		t.Fatalf("final org version = %+v (ok=%v), want %d", st, ok, top)
	}
	if got := firedRuleID(g, fmt.Sprintf("echo onlyv%d", top), "/home/u/proj"); got != fmt.Sprintf("ORG-V%d", top) {
		t.Fatalf("final top rule not live: fired %q, want ORG-V%d", got, top)
	}
}
