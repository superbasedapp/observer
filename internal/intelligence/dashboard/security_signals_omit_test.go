//go:build !sbo_omit_security && sbo_omit_security_deps

package dashboard

import (
	"context"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecuritySignalsWithoutTheOSVStore: with security.deps out of the
// build the exploit data is not in it either, so a dependency finding reads
// "Exploit data unavailable" and an unknown tier, never "not exploited".
func TestSecuritySignalsWithoutTheOSVStore(t *testing.T) {
	s, _ := newTestServer(t)
	if s.securityExploitLookup() != nil {
		t.Fatal("an exploit lookup without the OSV store")
	}
	f := secfinding.Finding{ID: "d", Category: policy.FindingVulnerableDependency, Rule: secfinding.Rule{ID: "CVE-2021-23337"}}
	sigs := s.securitySignals(context.Background(), store.New(s.db()), []secfinding.Finding{f}, map[string]string{"d": "npm lodash@4.17.20"}, nil)
	rows := []securityFindingJS{{ID: "d"}}
	applySecuritySignals(rows, sigs)
	if rows[0].Exploit == nil || !reflect.DeepEqual(rows[0].Exploit.Badges, []string{secexploit.BadgeUnavailable}) || rows[0].Reach.Level != "unknown" {
		t.Fatalf("%+v %+v", rows[0].Exploit, rows[0].Reach)
	}
}
