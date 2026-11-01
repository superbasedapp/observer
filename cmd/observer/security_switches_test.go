//go:build !sbo_omit_security

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSecurityWriteCheckSwitch (settings contract, lane sec-c3): with the
// write check on (the default) S-721 is in the composed pack; off, only
// S-721 leaves it and every other pillar rule stays.
func TestSecurityWriteCheckSwitch(t *testing.T) {
	all := securityPackRules(func(string) bool { return true }, nil)
	count := func(sec config.SecurityConfig) (s721, others int) {
		for _, r := range securityRulesWithSwitches(sec, all) {
			if r.ID == "S-721" {
				s721++
			} else {
				others++
			}
		}
		return s721, others
	}
	on := config.DefaultSecurityConfig()
	onS, onOthers := count(on)
	if onS == 0 || onOthers == 0 {
		t.Fatalf("default pack: S-721 rows %d, other rows %d", onS, onOthers)
	}
	off := on
	off.Secrets.WriteCheck = false
	offS, offOthers := count(off)
	if offS != 0 || offOthers != onOthers {
		t.Fatalf("write check off: S-721 rows %d (want 0), other rows %d (want %d)", offS, offOthers, onOthers)
	}
	commitOff := on
	commitOff.Secrets.CommitCheck = false
	if s, o := count(commitOff); s != onS || o != onOthers {
		t.Fatal("the commit check switches no guard rule")
	}
}
