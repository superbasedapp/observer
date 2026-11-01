package hook_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// T-847 registry-driven tamper gate. For EVERY integration row whose hook
// mechanism has a registry writer (hook.RegistryWrites), native and cross-OS
// "-windows" targets alike, it registers into a throwaway home and then
// applies each generic weakening a developer could make to the registered
// artifact. Each case must hold three properties:
//
//	(a) detection: before any re-registration the managed-integrity probe
//	    reports a risk that names the target and the file;
//	(b) repair: one auto-registration pass (Registry.Reconcile) either writes
//	    the canonical artifact back and reports the repair, or the risk is
//	    still reported afterwards. It must never adopt the weakened artifact
//	    as the new baseline (the re-baseline defect);
//	(c) report: a repaired case carries a hook_repaired item naming the
//	    target and the file.
//
// The weakenings are generic over file formats: delete the artifact, delete
// it together with hook_checksums.json (audit c3), remove one Observer entry
// (JSON artifacts), narrow a "*" matcher (formats that carry one), append an
// argument to the Observer command, and point the command at a binary that
// is not observer. A weakening that does not apply to a format (no matcher,
// no JSON) is skipped for that target, never counted as covered.

// tamperToolDirs are the vendor config directories created in every
// throwaway home so each writer finds its install (hookparity's list).
var tamperToolDirs = []string{
	".claude", ".cursor", ".codex", ".gemini", filepath.Join(".gemini", "config"),
	filepath.Join(".gemini", "antigravity-cli"),
	".qwen", ".factory", ".qoder", filepath.Join(".config", "poolside"),
	filepath.Join(".codeium", "windsurf"), ".commandcode",
	".grok", ".copilot", ".agents", ".junie", filepath.Join(".config", "crush"),
	".openinterpreter", ".zcode", ".vibe", ".cline", filepath.Join(".config", "devin"), filepath.Join(".config", "muse"),
	".kimi-code", ".kiro", filepath.Join(".config", "opencode"), filepath.Join(".config", "kilo"),
	filepath.Join(".pi", "agent"),
}

// tamperEnv is one throwaway home plus a registry pinned to it.
type tamperEnv struct {
	home, checksums, binary, fake string
	reg                           *hook.Registry
	tracker                       *hook.RepairTracker
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newTamperEnv(t *testing.T) *tamperEnv {
	t.Helper()
	return newTamperEnvWith(t, false)
}

// newTamperEnvWith is newTamperEnv with hook.Options.RepairOwnedArtifacts set
// to managed: true is a managed node's heartbeat repair pass (T-872).
func newTamperEnvWith(t *testing.T, managed bool) *tamperEnv {
	t.Helper()
	home := t.TempDir()
	winHome := filepath.Join(home, "winhome", "Users", "dev")
	for _, base := range []string{home, winHome} {
		for _, d := range tamperToolDirs {
			if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	bin := filepath.Join(home, "opt", "observer", "bin", "observer")
	fake := filepath.Join(home, "opt", "allow", "bin", "allowall")
	writeExecutable(t, bin)
	writeExecutable(t, fake)
	e := &tamperEnv{
		home:      home,
		checksums: filepath.Join(home, ".observer", "hook_checksums.json"),
		binary:    bin,
		fake:      fake,
		tracker:   &hook.RepairTracker{},
	}
	r, err := hook.NewRegistry(hook.Options{
		BinaryPath:             bin,
		HomeDir:                home,
		ChecksumsPath:          e.checksums,
		WSLDistro:              "Ubuntu-Tamper",
		KeepEquivalentHooks:    true,
		WindowsCursorHome:      winHome,
		WindowsClaudeHome:      winHome,
		WindowsCodexHome:       winHome,
		WindowsGeminiHome:      winHome,
		WindowsQwenHome:        winHome,
		WindowsFactoryHome:     winHome,
		WindowsQoderHome:       winHome,
		WindowsPoolsideHome:    winHome,
		WindowsCommandCodeHome: winHome,
		RepairOwnedArtifacts:   managed,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.reg = r
	return e
}

// tamperTargets lists every registration target the registry rows with a
// writer mechanism produce, plus the rows that cannot be covered and why.
func tamperTargets(t *testing.T) (targets []string, uncovered map[string]string) {
	t.Helper()
	uncovered = map[string]string{}
	probe := newTamperEnv(t)
	for _, c := range integration.Capabilities() {
		m := c.Hook.Mechanism
		if m == integration.HookNone {
			continue
		}
		if !hook.RegistryWrites(m) {
			uncovered[c.Tool] = "mechanism " + string(m) + " has no hook.Registry writer (written by its own installer, or no config artifact)"
			continue
		}
		for _, target := range []string{c.Tool, c.Tool + "-windows"} {
			res := probe.reg.Probe(target)
			if res.Error != nil && (target != c.Tool || strings.Contains(res.Error.Error(), "not supported")) {
				// No cross-OS writer for this row (the credential-file
				// guard answers an unknown target with its own safe error).
				continue
			}
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	return targets, uncovered
}

// installed registers target into env once (the first auto-registration) and
// returns the canonical artifact bytes. ok is false when the writer wrote
// nothing on this host (a skip), which the caller records as not covered.
func (e *tamperEnv) installed(t *testing.T, target string) (hook.RegistrationResult, []byte, bool) {
	t.Helper()
	rec := e.reg.Reconcile(target, e.tracker, time.Now())
	res := rec.Result
	if res.Error != nil || res.Skipped || res.ConfigPath == "" {
		return res, nil, false
	}
	if len(rec.Repaired) != 0 {
		t.Fatalf("%s: a first install was reported as a repair: %v", target, rec.Repaired)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		return res, nil, false
	}
	return res, body, true
}

// inspect runs the managed-integrity probe the way cmd/observer does: the
// expected targets come from a dry run of the same registration.
func (e *tamperEnv) inspect(target string, now time.Time) diag.CaptureIntegritySignals {
	p := e.reg.Probe(target)
	exp := []diag.ExpectedHook{{Tool: p.Tool, ConfigPath: p.ConfigPath, Drift: hook.DriftEvents(p)}}
	if p.Error != nil || p.Skipped {
		exp[0].Drift = nil
	}
	return diag.InspectCaptureIntegrityWith(e.home, diag.CaptureIntegrityOptions{
		BinaryPath: e.binary,
		Expected:   exp,
		Now:        now,
	})
}

// locatedRisk returns the first located item naming target, or false.
func locatedRisk(sig diag.CaptureIntegritySignals, target string, labels ...string) (orgcontract.CaptureRiskItem, bool) {
	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}
	for _, it := range sig.Items {
		if (len(want) == 0 || want[it.Risk]) && it.Tool == target && it.File != "" {
			return it, true
		}
	}
	return orgcontract.CaptureRiskItem{}, false
}

// weakening is one generic tamper. apply mutates the artifact and reports
// whether the weakening applies to this format.
type weakening struct {
	name  string
	apply func(e *tamperEnv, target, path string, body []byte) bool
	// managed runs the case on a managed node's repair pass
	// (hook.Options.RepairOwnedArtifacts, T-872).
	managed bool
	// neutralises marks the T-872 weakening: Observer's artifact is kept in
	// place but no longer runs observer (an empty plugin module, a stubbed
	// command under Observer's own entry name).
	neutralises bool
}

var matcherStar = regexp.MustCompile(`("matcher"\s*:\s*"\*")|(matcher:\s*['"]?\*['"]?)|(matcher\s*=\s*"\*")|("match"\s*:\s*"\*")|(match\s*=\s*"\*")`)

var observerArgv = regexp.MustCompile(` hook [a-z0-9-]+ [A-Za-z0-9_.-]+`)

func weakenings() []weakening {
	return []weakening{
		{name: "delete-artifact", apply: func(_ *tamperEnv, _, path string, _ []byte) bool {
			return os.Remove(path) == nil
		}},
		{name: "delete-artifact-and-registry", apply: func(e *tamperEnv, _, path string, _ []byte) bool {
			return os.Remove(path) == nil && os.Remove(e.checksums) == nil
		}},
		{name: "remove-one-entry", apply: func(_ *tamperEnv, _, path string, body []byte) bool {
			out, ok := removeOneObserverEntry(body)
			return ok && os.WriteFile(path, out, 0o600) == nil
		}},
		{name: "add-short-timeout", apply: func(_ *tamperEnv, _, path string, body []byte) bool {
			out, ok := addFieldToObserverEntry(body)
			return ok && os.WriteFile(path, out, 0o600) == nil
		}},
		{name: "narrow-matcher", apply: func(_ *tamperEnv, _, path string, body []byte) bool {
			loc := matcherStar.FindIndex(body)
			if loc == nil {
				return false
			}
			seg := string(body[loc[0]:loc[1]])
			seg = strings.Replace(seg, "*", "Read", 1)
			out := append(append(append([]byte{}, body[:loc[0]]...), seg...), body[loc[1]:]...)
			return os.WriteFile(path, out, 0o600) == nil
		}},
		{name: "extra-argument", apply: func(_ *tamperEnv, _, path string, body []byte) bool {
			loc := observerArgv.FindIndex(body)
			if loc == nil {
				return false
			}
			out := append(append(append([]byte{}, body[:loc[1]]...), " --weakened"...), body[loc[1]:]...)
			return os.WriteFile(path, out, 0o600) == nil
		}},
		{name: "foreign-binary", apply: func(e *tamperEnv, _, path string, body []byte) bool {
			for _, form := range []string{e.binary, filepath.ToSlash(e.binary)} {
				if i := bytes.Index(body, []byte(form)); i >= 0 {
					out := append(append(append([]byte{}, body[:i]...), filepath.ToSlash(e.fake)...), body[i+len(form):]...)
					return os.WriteFile(path, out, 0o600) == nil
				}
			}
			return false
		}},
		{name: "neutralise", apply: neutraliseWeakening, neutralises: true},
		{name: "neutralise-managed", apply: neutraliseWeakening, neutralises: true, managed: true},
	}
}

// neutraliseWeakening is the T-872 tamper (re-test E1): Observer's artifact
// stays where it is but no longer runs observer.
func neutraliseWeakening(e *tamperEnv, _, path string, body []byte) bool {
	out, ok := neutraliseArtifact(body, path, e.binary)
	return ok && os.WriteFile(path, out, 0o600) == nil
}

// neutraliseArtifact returns body with Observer's hook neutralised: a plugin
// module (.ts / .js) becomes an empty module, and in any other format every
// command that runs binary is stubbed to /bin/true while every other byte,
// including Observer's entry name, stays. ok is false when nothing changed.
func neutraliseArtifact(body []byte, path, binary string) ([]byte, bool) {
	switch filepath.Ext(path) {
	case ".ts", ".js", ".mjs", ".cjs":
		return []byte("export default {};\n"), true
	}
	lines := strings.SplitAfter(string(body), "\n")
	changed := false
	for i, l := range lines {
		for _, form := range []string{binary, filepath.ToSlash(binary)} {
			at := strings.Index(l, form)
			if at < 0 {
				continue
			}
			end := len(strings.TrimRight(l, "\r\n"))
			if at > 0 && (l[at-1] == '"' || l[at-1] == '\'') {
				if q := strings.IndexByte(l[at:], l[at-1]); q >= 0 {
					end = at + q
				}
			}
			lines[i] = l[:at] + "/bin/true" + l[end:]
			changed = true
			break
		}
	}
	return []byte(strings.Join(lines, "")), changed
}

// ownedByNameTargets are the registration targets whose artifact Observer
// owns by NAME (ownership.go identityOwnedName): a file Observer names, or
// an entry Observer names inside a shared file. A managed repair pass must
// rewrite a neutralised one; an individual node must keep refusing it.
var ownedByNameTargets = map[string]bool{
	"opencode": true, "kilo-code-cli": true, "pi": true, "cline-cli": true,
	"command-code": true, "antigravity-cli": true, "mistral-code": true,
	"poolside": true, "poolside-windows": true,
	"grok": true, "copilot-cli": true, "goose": true, "crush": true,
}

// removeOneObserverEntry deletes the first JSON array element whose encoding
// names an observer `hook` invocation. ok is false for a non-JSON artifact or
// one with no such element.
func removeOneObserverEntry(body []byte) ([]byte, bool) {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	removed := false
	var walk func(v any) any
	walk = func(v any) any {
		if removed {
			return v
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				x[k] = walk(x[k])
			}
			return x
		case []any:
			for i, el := range x {
				enc, _ := json.Marshal(el)
				if _, isMap := el.(map[string]any); isMap && observerArgv.Match(enc) && !bytes.Contains(enc, []byte(`"hooks":{`)) {
					removed = true
					return append(x[:i:i], x[i+1:]...)
				}
			}
			for i := range x {
				x[i] = walk(x[i])
			}
			return x
		}
		return v
	}
	doc = walk(doc)
	if !removed {
		return nil, false
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return out, err == nil
}

// addFieldToObserverEntry sets a one-millisecond "timeout" on the first JSON
// object that directly carries an observer `hook` command string, the shape
// of a hook that times out before it can deny. ok is false for a non-JSON
// artifact or one without such an object.
func addFieldToObserverEntry(body []byte) ([]byte, bool) {
	var doc any
	if json.Unmarshal(body, &doc) != nil {
		return nil, false
	}
	done := false
	var walk func(v any)
	walk = func(v any) {
		if done {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for _, val := range x {
				if s, ok := val.(string); ok && observerArgv.MatchString(s) {
					x["timeout"] = 0.001
					done = true
					return
				}
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k])
			}
		case []any:
			for _, el := range x {
				walk(el)
			}
		}
	}
	walk(doc)
	if !done {
		return nil, false
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return out, err == nil
}

// TestEveryHookMechanismReportsAndRepairsTamper is the T-847 gate.
func TestEveryHookMechanismReportsAndRepairsTamper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the generic weakenings use POSIX executables")
	}
	targets, uncovered := tamperTargets(t)
	if len(targets) == 0 {
		t.Fatal("no registration targets found in the integration registry")
	}
	for tool, why := range uncovered {
		t.Logf("not covered: %s: %s", tool, why)
	}
	covered := map[string]int{}
	for _, target := range targets {
		for _, w := range weakenings() {
			t.Run(target+"/"+w.name, func(t *testing.T) {
				e := newTamperEnvWith(t, w.managed)
				first, canonical, ok := e.installed(t, target)
				if !ok {
					t.Skipf("writer wrote nothing on this host: err=%v skipped=%v %s", first.Error, first.Skipped, first.SkipReason)
				}
				path := first.ConfigPath
				if !w.apply(e, target, path, canonical) {
					t.Skipf("%s does not apply to this artifact", w.name)
				}
				covered[target]++
				now := time.Now()

				// (a) detection, before any re-registration.
				before := e.inspect(target, now)
				if _, ok := locatedRisk(before, target); !ok {
					if _, okReg := locatedRisk(before, diag.HookRegistryTool, orgcontract.CaptureRiskHookRegistryMissing); !okReg {
						t.Fatalf("tamper not reported with tool+file: risks=%v items=%+v", before.Risks, before.Items)
					}
				}

				// (b) one auto-registration pass.
				e.reg.BeginPass(e.tracker, now)
				rec := e.reg.Reconcile(target, e.tracker, now)
				after := e.inspect(target, now)
				healed, _ := os.ReadFile(path)
				probe := e.reg.Probe(target)
				canonicalAgain := rec.Result.Error == nil && probe.Error == nil && len(hook.DriftEvents(probe)) == 0
				// T-872: a neutralised artifact Observer owns by name is
				// repaired on a managed node and refused on an individual one.
				if w.neutralises && ownedByNameTargets[target] {
					if w.managed && !(canonicalAgain && len(rec.Repaired) > 0) {
						t.Fatalf("managed repair pass did not repair a neutralised owned artifact: err=%v repaired=%v drift=%v", rec.Result.Error, rec.Repaired, hook.DriftEvents(probe))
					}
					if !w.managed && (rec.Result.Error == nil || len(rec.Repaired) > 0) {
						t.Fatalf("individual node rewrote a neutralised owned artifact: err=%v repaired=%v", rec.Result.Error, rec.Repaired)
					}
				}
				switch {
				case canonicalAgain && len(rec.Repaired) > 0:
					// (c) the repair is reported, naming tool and file.
					it, ok := locatedRisk(after, target, orgcontract.CaptureRiskHookRepaired)
					if !ok {
						t.Fatalf("repair not carried by the report: items=%+v", after.Items)
					}
					if !strings.HasPrefix(it.File, "~/") && !strings.HasPrefix(it.File, "~win/") {
						t.Fatalf("repair file label %q is not home-relative", it.File)
					}
				case canonicalAgain && bytes.Equal(normalizeArtifact(healed), normalizeArtifact(canonical)):
					t.Fatalf("artifact restored but the repair was not classified as one: added=%v rewrites=%+v", rec.Result.HooksAdded, rec.Result.Rewrites)
				case canonicalAgain:
					t.Fatalf("weakened artifact silently adopted as the new baseline:\n--- canonical ---\n%s\n--- now ---\n%s\nrisks=%v items=%+v rec=%+v",
						canonical, healed, after.Risks, after.Items, rec.Result)
				default:
					// Not repaired (a foreign entry blocks the writer): the
					// weakening must still be reported.
					if _, ok := locatedRisk(after, target, orgcontract.CaptureRiskHookRegistrationDrift,
						orgcontract.CaptureRiskHookConfigChanged, orgcontract.CaptureRiskHookRegistrationError,
						orgcontract.CaptureRiskHookConfigMissing); !ok {
						t.Fatalf("weakened artifact neither repaired nor reported:\n--- now ---\n%s\nrisks=%v items=%+v rec=%+v",
							healed, after.Risks, after.Items, rec.Result)
					}
				}
			})
		}
	}
	for _, target := range targets {
		if covered[target] == 0 {
			t.Logf("target %s: no weakening applied (writer skipped on this host)", target)
		}
	}
}

// normalizeArtifact makes a JSON artifact comparable semantically (key order
// and indentation); any other format is compared byte for byte.
func normalizeArtifact(b []byte) []byte {
	var v any
	if json.Unmarshal(b, &v) == nil {
		out, err := json.Marshal(v)
		if err == nil {
			return out
		}
	}
	return b
}
