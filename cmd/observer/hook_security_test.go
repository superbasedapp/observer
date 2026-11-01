//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// writeGuardPosture signs a guard posture beside cfgPath saying whether
// the security module is active.
func writeGuardPosture(t *testing.T, cfgPath string, active bool) {
	t.Helper()
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := guardposture.Posture{Source: "test", SecurityRecorded: true, SecurityActive: active, WrittenAt: time.Now()}
	if _, err := guardposture.Write(guardposture.PosturePath(cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
}

func writeEvent(root, cwd string) *policy.Event {
	return &policy.Event{Kind: policy.KindFileAccess, ActionType: models.ActionWriteFile, Target: filepath.Join(cwd, "a.go"), ProjectRoot: root, Cwd: cwd}
}

// TestSecurityHookInertWhileInactive: while the signed guard posture does
// not say the module is active, the enrich step leaves Event.Security nil
// (its contract in internal/policy/event.go), composes no rule pack and
// creates nothing under the security directory (audit P-002 finding 3).
func TestSecurityHookInertWhileInactive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, cfgPath string)
	}{
		{"no daemon", func(*testing.T, string) {}},
		{"inactive", func(t *testing.T, cfgPath string) { writeGuardPosture(t, cfgPath, false) }},
		// A guard posture that does not verify cannot say the module is
		// active: the hook reads it as ModuleUnverified, composes nothing
		// and writes nothing (guard itself falls back to the config, and
		// the daemon repairs the file within RefreshInterval and records
		// the tamper; lane SEC-GATEFIX milestone 3).
		{"tampered guard posture", func(t *testing.T, cfgPath string) {
			writeGuardPosture(t, cfgPath, true)
			path := guardposture.PosturePath(cfgPath)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"source": "test"`, `"source": "edited"`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"guard posture removed, key kept", func(t *testing.T, cfgPath string) {
			writeGuardPosture(t, cfgPath, true)
			if err := os.Remove(guardposture.PosturePath(cfgPath)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			tc.setup(t, cfgPath)
			pe := writeEvent("/work/project", "/work/project")
			securityToolGateEnrich(cfgPath, "claude-code", "PreToolUse", nil)(pe)
			if pe.Security != nil {
				t.Fatalf("Event.Security = %+v, want nil while inactive", pe.Security)
			}
			if rules := securityHookPackRules(cfgPath); len(rules) != 0 {
				t.Fatalf("%d pack rules composed while inactive", len(rules))
			}
			if _, err := os.Stat(filepath.Join(dir, secposture.DirName)); !os.IsNotExist(err) {
				t.Fatalf("security directory touched while inactive: %v", err)
			}
		})
	}
}

// TestSecuritySidecarSkipsWithoutRoot: with the module active, an event
// with no project root reads nothing and raises no marker; its facts are
// unknown with the module root's pack, so the commit gate still asks.
func TestSecuritySidecarSkipsWithoutRoot(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeGuardPosture(t, cfgPath, true)
	p := securityHostProviders(cfgPath)
	sec, err := p.Sidecar(context.Background(), hookctx.Request{})
	if err != nil || sec.Posture != policy.SecurityPostureUnknown || len(sec.Packs) != 1 || sec.Packs[0] != secposture.RootPack {
		t.Fatalf("no root: %+v, %v", sec, err)
	}
	if err := p.Dirty(context.Background(), ""); err == nil {
		t.Fatal("the dirty provider must refuse an empty project root")
	}
	if _, err := os.Stat(filepath.Join(dir, secposture.DirName)); !os.IsNotExist(err) {
		t.Fatalf("security directory touched without a project root: %v", err)
	}
	pe := writeEvent("", "")
	securityToolGateEnrich(cfgPath, "claude-code", "PreToolUse", nil)(pe)
	if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureUnknown {
		t.Fatalf("active, no root: %+v", pe.Security)
	}
	if len(securityHookPackRules(cfgPath)) == 0 {
		t.Fatal("an active module composes its pack")
	}
}

// TestHookProjectRootResolvesTheRepository: the dirty marker and posture
// are named after the repository the working directory belongs to, never
// after the working directory itself (audit P-002 finding 11).
func TestHookProjectRootResolvesTheRepository(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "pkg", "x")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := hookProjectRoot(writeEvent("", sub)); got != want {
		t.Fatalf("hookProjectRoot(subdir) = %q, want %q", got, want)
	}
	if got := hookProjectRoot(writeEvent("/given", sub)); got != "/given" {
		t.Fatalf("an event's own root wins: %q", got)
	}
	if got := hookProjectRoot(writeEvent("", "")); got != "" {
		t.Fatalf("no root and no cwd: %q", got)
	}
}
