package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOrgReportsNameOnlyRefusedCrossTenancyGrants (OSH-R-013, operator
// ruling P-204): `observer org status` and `observer org grant show` print a
// "Managed: REFUSED" line, naming why, only for a managed-consent grant that
// would cross tenancy. A node whose org switched it to enterprise is managed
// and prints nothing, and so does a node whose org switched back.
func TestOrgReportsNameOnlyRefusedCrossTenancyGrants(t *testing.T) {
	auth := []string{govern.AuthorityEnforceBudget}
	row := func(org string, gen int64, authority []string) store.EnrolmentGrant {
		return store.EnrolmentGrant{OrgID: org, ConsentMode: govern.ConsentManaged, Authority: authority, ReplacementGeneration: gen}
	}
	individualA := &store.Enrolment{OrgID: "A", Tenancy: govern.TenancyIndividual}
	cases := []struct {
		name string
		g    *govern.Grant
		want string
	}{
		{"switched org", grantFromStore(row("A", 1, auth), individualA), ""},
		{"switched back", grantFromStore(row("A", 2, nil), individualA), ""},
		{"managed enrolment", grantFromStore(row("A", 0, auth), &store.Enrolment{OrgID: "A", Tenancy: govern.TenancyManaged}), ""},
		{"grant from another org", grantFromStore(row("B", 1, auth), individualA), govern.RefusalOtherOrg},
		{"individual enrolment's own grant", grantFromStore(row("A", 0, auth), individualA), govern.RefusalIndividualEnrolment},
	}
	for _, c := range cases {
		c.g.OrgName = "Acme"
		var show bytes.Buffer
		printGrantShow(&show, grantShowReport{Live: govern.LiveIdentity{Enrolled: true}, Grant: c.g}, config.Default(), "")
		var status bytes.Buffer
		printOrgStatus(&status, orgStatusReport{
			State:       orgclient.EnrolmentState{Enrolled: true, OrgID: "A"},
			TenancyLine: managedConsentRefusalLine(c.g),
		})
		for name, out := range map[string]string{"grant show": show.String(), "org status": status.String()} {
			has := strings.Contains(out, "Managed:      REFUSED")
			if has != (c.want != "") || (c.want != "" && !strings.Contains(out, c.want)) {
				t.Errorf("%s, %s: refusal line present=%v, want reason %q:\n%s", c.name, name, has, c.want, out)
			}
			if strings.Contains(out, "Managed:      NO") {
				t.Errorf("%s, %s: the old demotion message is back:\n%s", c.name, name, out)
			}
		}
	}
}
