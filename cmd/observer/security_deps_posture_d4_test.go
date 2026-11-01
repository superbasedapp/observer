//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// TestDepsAcceptBeforeFirstStartIsNotTamper (live check macOS 2026-10-22,
// D4): on a fresh node, an accept before the first `observer start` creates
// the posture key; that start initialises the posture and reports no
// posture or org lock tamper. A posture removed after one existed still
// does.
func TestDepsAcceptBeforeFirstStartIsNotTamper(t *testing.T) {
	obs := t.TempDir()
	cp := filepath.Join(obs, "config.toml")
	if _, err := depsRecordSigningKey(filepath.Join(obs, "security")); err != nil {
		t.Fatal(err)
	}
	w := &guardPostureWriter{}
	if _, err := w.publish(cp, guardposture.Posture{OrgLock: true, WrittenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := w.takeTampers(); len(got) != 0 {
		t.Fatalf("the first start after an accept reported a posture tamper: %v", got)
	}
	if got := w.takeExtraTampers(); len(got) != 0 {
		t.Fatalf("the first start after an accept reported an org lock tamper: %+v", got)
	}
	if err := os.Remove(guardposture.PosturePath(cp)); err != nil {
		t.Fatal(err)
	}
	w2 := &guardPostureWriter{}
	if _, err := w2.publish(cp, guardposture.Posture{OrgLock: true, WrittenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got := w2.takeTampers()
	if len(got) != 1 || !strings.Contains(got[0], "posture missing while its key exists") {
		t.Fatalf("a removed posture was not reported: %v", got)
	}
}
