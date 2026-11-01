//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// fakeNativeFiles stands in the host's settings files and policy.
func fakeNativeFiles(t *testing.T, goos string, files map[string]string, policy string) {
	t.Helper()
	prevRead, prevGOOS, prevHome, prevPolicy := nativeReadSetting, nativeGOOS, nativeHome, vendorForcedPolicy
	nativeReadSetting = func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return []byte(b), nil
		}
		return nil, fs.ErrNotExist
	}
	nativeGOOS = goos
	nativeHome = func() (string, error) { return "/home/dev", nil }
	vendorForcedPolicy = func() string { return policy }
	t.Cleanup(func() {
		nativeReadSetting, nativeGOOS, nativeHome, vendorForcedPolicy = prevRead, prevGOOS, prevHome, prevPolicy
	})
}

const claudeForced = `{"sandbox":{"enabled":true,"failIfUnavailable":true}}`

// TestVendorForcedNative: a managed policy that forces Claude Code's
// sandbox on refuses a bwrap and a Seatbelt launch under both values of
// vendor_forced_native, naming the setting; with no file, or a file that
// does not force it, the launch behaves as before (unjudged).
func TestVendorForcedNative(t *testing.T) {
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	for _, policy := range []string{sandboxselect.VendorForcedNestOrRefuse, sandboxselect.VendorForcedRefuse} {
		fakeNativeFiles(t, "linux", map[string]string{"/etc/claude-code/managed-settings.json": claudeForced}, policy)
		v, judged := sandboxNativeVerdictFor(bw, "claude-code", vocab.TierInternet)
		err := sandboxNativeRefusal("claude-code", v)
		if !judged || v.Outcome != sandboxselect.NativeRefuse || err == nil || !strings.Contains(err.Error(), "vendor_forced_native = "+policy) {
			t.Fatalf("%s, bwrap: %+v %v", policy, v, err)
		}
		fakeNativeFiles(t, "darwin", map[string]string{"/Library/Application Support/ClaudeCode/managed-settings.json": claudeForced}, policy)
		if n := seatbeltNative("claude-code"); !n.VendorForced || n.ForcedPolicy != policy {
			t.Fatalf("%s, seatbelt facts: %+v", policy, n)
		}
	}
	// A forced sandbox that nests runs, recorded org_forced.
	fakeNativeFiles(t, "linux", map[string]string{"/etc/claude-code/managed-settings.json": claudeForced}, sandboxselect.VendorForcedNestOrRefuse)
	oci, _ := sandboxbackend.Get(sandboxbackend.BackendOCIRunc)
	if v, judged := sandboxNativeVerdictFor(oci, "claude-code", vocab.TierInternet); !judged || sandboxselect.NativeStateFor(v) != vocab.NativeOrgForced {
		t.Fatalf("oci, forced: %+v", v)
	}
	for name, files := range map[string]map[string]string{
		"no managed file":      {},
		"enabled only":         {"/etc/claude-code/managed-settings.json": `{"sandbox":{"enabled":true}}`},
		"not JSON":             {"/etc/claude-code/managed-settings.json": `sandbox=true`},
		"another OS's path":    {"/Library/Application Support/ClaudeCode/managed-settings.json": claudeForced},
		"a string, not a bool": {"/etc/claude-code/managed-settings.json": `{"sandbox":{"enabled":"true","failIfUnavailable":true}}`},
	} {
		fakeNativeFiles(t, "linux", files, sandboxselect.VendorForcedRefuse)
		if _, judged := sandboxNativeVerdictFor(bw, "claude-code", vocab.TierInternet); judged {
			t.Errorf("%s: judged", name)
		}
	}
}

// TestNativeWeakModeOnlyWhenTheUserTurnedItOn: the user's setting is read
// only for a row with a grounded per-run weak mode, and weak is the state
// only when that setting reads on.
func TestNativeWeakModeOnlyWhenTheUserTurnedItOn(t *testing.T) {
	skipDriverOffHost(t, "the Linux native-sandbox fake")
	row := integration.NativeSandbox{
		Needs: []integration.NativeSandboxNeed{integration.NeedFreshProc},
		WeakMode: integration.NativeSwitch{
			Kind: integration.NativeSwitchFlag, Value: "--weak-sandbox",
			SourceURL: "https://example.com/doc", VerifiedOn: "2026-10-23",
		},
		UserOn: &integration.NativeSettingProbe{
			Paths: map[string]string{"*": "~/.agent/settings.json"}, Keys: [][]string{{"sandbox", "enabled"}},
			SourceURL: "https://example.com/doc", VerifiedOn: "2026-10-23",
		},
	}
	fakeNativeFiles(t, "linux", map[string]string{"/home/dev/.agent/settings.json": `{"sandbox":{"enabled":true}}`}, "")
	if f := nativeFactsFor(row); !f.userOn || f.forced {
		t.Fatalf("on: %+v", f)
	}
	bw, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	v := sandboxselect.NativeNesting(bw, vocab.TierInternet, sandboxselect.NativeSandbox{Present: true, NeedsFreshProc: true, PerRunWeak: true, UserOn: true})
	if sandboxselect.NativeStateFor(v) != vocab.NativeWeak {
		t.Fatalf("weak: %+v", v)
	}
	fakeNativeFiles(t, "linux", map[string]string{"/home/dev/.agent/settings.json": `{"sandbox":{"enabled":false}}`}, "")
	if f := nativeFactsFor(row); f.userOn {
		t.Fatal("off read as on")
	}
	// Without a grounded weak mode the user's file is never read.
	row.WeakMode.SourceURL = ""
	read := false
	nativeReadSetting = func(string) ([]byte, error) { read = true; return nil, errors.New("x") }
	if f := nativeFactsFor(row); f.userOn || read {
		t.Fatal("the user's setting was read for a row with no grounded weak mode")
	}
}

// TestNativeSwitchOnBackends (lane SBX-P3D): a NativeDisable verdict with a
// grounded flag switch runs on the rows that call sandboxNativeRefusal
// (bwrap, oci, mxc, apple container); a global setting or an environment
// switch there is still refused.
func TestNativeSwitchOnBackends(t *testing.T) {
	disable := sandboxselect.NativeVerdict{Outcome: sandboxselect.NativeDisable, Rule: "N11"}
	if err := sandboxNativeRefusal("codex", disable); err != nil {
		t.Fatalf("codex flag switch refused: %v", err)
	}
	if err := sandboxNativeRefusal("copilot-cli", disable); err != nil {
		t.Fatalf("copilot-cli flag switch refused: %v", err)
	}
	for _, tool := range []string{"droid", "kiro-cli", "qwen-code", "gemini-cli"} {
		if err := sandboxNativeRefusal(tool, disable); err == nil {
			t.Errorf("%s: a switch this backend cannot apply was accepted", tool)
		}
	}
	weak := sandboxselect.NativeVerdict{Outcome: sandboxselect.NativeWeakMode, Rule: "N11"}
	if err := sandboxNativeRefusal("codex", weak); err == nil {
		t.Error("weak mode accepted for a row with no weak switch")
	}
}

// TestSeatbeltCodexGetsItsFlag: Codex under Seatbelt (MAC-1 refused it
// before lane SBX-P3D) gets its grounded flag and records
// disabled_by_observer from the same decision.
func TestSeatbeltCodexGetsItsFlag(t *testing.T) {
	fakeNativeFiles(t, "darwin", nil, "")
	dec := decideSeatbeltNative(t, "codex")
	if dec.Outcome != "disable_flag" || strings.Join(dec.Args, " ") != "--sandbox danger-full-access" {
		t.Fatalf("%+v", dec)
	}
	if st := seatbeltNativeState("codex", dec); st != vocab.NativeDisabledByObserver {
		t.Fatalf("state %q", st)
	}
	args, err := integration.NativeSwitchArgsForState("codex", seatbeltNativeState("codex", dec))
	if err != nil || strings.Join(args, " ") != "--sandbox danger-full-access" {
		t.Fatalf("composition: %v %v", args, err)
	}
	// The CLI path and the dashboard path give the same argv.
	cli := sandboxCLIInnerArgv([]string{"wrap", "--"}, "/bin/observer", "codex", integration.AppendNativeArgs(nil, args))
	dash := append([]string{"wrap", "--", "/bin/observer", "codex"}, integration.AppendNativeArgs(nil, args)...)
	if strings.Join(cli, " ") != strings.Join(dash, " ") {
		t.Fatalf("cli %v, dashboard %v", cli, dash)
	}
	// Tools kept today stay kept: Claude Code (off by default) is unjudged.
	if dec := decideSeatbeltNative(t, "claude-code"); dec.Outcome != "unjudged" {
		t.Fatalf("claude-code: %+v", dec)
	}
}

func decideSeatbeltNative(t *testing.T, tool string) sandboxsbpl.NativeDecision {
	t.Helper()
	return sandboxsbpl.DecideNative(seatbeltNative(tool))
}
