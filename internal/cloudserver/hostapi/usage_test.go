package hostapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

func TestUsageDays(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 0, 30, 0, 0, time.FixedZone("x", 3*3600)) // 2026-11-14 21:30 UTC
	if got := UsageDays(now, 0); strings.Join(got, ",") != "2026-11-13,2026-11-14" {
		t.Fatalf("UsageDays(default) = %v", got)
	}
	if got := UsageDays(now, 3); strings.Join(got, ",") != "2026-11-12,2026-11-13,2026-11-14" {
		t.Fatalf("UsageDays(3) = %v", got)
	}
}

func TestUsageProbe(t *testing.T) {
	t.Parallel()
	r, err := UsageProbe("2026-11-14")
	if err != nil || r.Method != "GET" || r.Path != pc.PathUsage || r.RawQuery != "day=2026-11-14" || len(r.Body) != 0 {
		t.Fatalf("UsageProbe = %+v, %v", r, err)
	}
	for _, bad := range []string{"", "2026-13-01", "2026-11-14&x=1", "14/11/2026"} {
		if _, err := UsageProbe(bad); !errors.Is(err, ErrBadIntent) {
			t.Errorf("UsageProbe(%q) = %v, want ErrBadIntent", bad, err)
		}
	}
}

// TestReadUsage: only a verified usage answer for the asked day is read,
// and its digest is the SHA-256 of the exact signed body.
func TestReadUsage(t *testing.T) {
	t.Parallel()
	body := mustJSON(t, pc.UsageResponse{Day: "2026-11-14", Tenants: []pc.TenantUsage{{TenantID: testOrg, Sessions: 3}}})
	rep, ok := ReadUsage(verified(body), "2026-11-14")
	sum := sha256.Sum256(body)
	if !ok || rep.Digest != hex.EncodeToString(sum[:]) || len(rep.Report.Tenants) != 1 || rep.Report.Tenants[0].Sessions != 3 {
		t.Fatalf("ReadUsage = %+v, %v", rep, ok)
	}
	for name, a := range map[string]Answer{
		"unverified":    {Kind: AnswerUnverified, Body: body},
		"transport":     {Kind: AnswerTransport},
		"refusal":       verified(refusalBody(t, pc.CodeUnavailable)),
		"not json":      verified([]byte(`[]`)),
		"another day":   verified(mustJSON(t, pc.UsageResponse{Day: "2026-11-13"})),
		"malformed day": verified([]byte(`{"day":"yesterday","tenants":[]}`)),
	} {
		if _, ok := ReadUsage(a, "2026-11-14"); ok {
			t.Errorf("%s: read as a usage report", name)
		}
	}
}

// TestUsageRules is one case per usageRules row, in table order.
func TestUsageRules(t *testing.T) {
	t.Parallel()
	good := pc.TenantUsage{TenantID: testOrg, ActiveSeatMemberIDs: []string{"m1"}, Sessions: 1, Members: 2}
	cases := []struct {
		rule string
		e    UsageEntry
		want UsageVerdict
	}{
		{"malformed", UsageEntry{Usage: pc.TenantUsage{TenantID: "a/b"}, PlacedHere: true}, UsageDropMalformed},
		{"not_placed_here", UsageEntry{Usage: good}, UsageDropNotPlaced},
		{"duplicate", UsageEntry{Usage: good, PlacedHere: true, SeenBefore: true}, UsageDropDuplicate},
		{"record", UsageEntry{Usage: good, PlacedHere: true}, UsageRecord},
	}
	if len(cases) != len(usageRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(usageRules))
	}
	for i, tc := range cases {
		if usageRules[i].name != tc.rule {
			t.Fatalf("case %d is %s, rule %d is %s", i, tc.rule, i, usageRules[i].name)
		}
		if got := JudgeUsage(tc.e); got != tc.want {
			t.Errorf("%s: JudgeUsage = %s, want %s", tc.rule, got, tc.want)
		}
	}
	for name, u := range map[string]pc.TenantUsage{
		"negative sessions": {TenantID: testOrg, Sessions: -1},
		"negative members":  {TenantID: testOrg, Members: -1},
		"negative machines": {TenantID: testOrg, MachineIdentities: -1},
		"empty seat id":     {TenantID: testOrg, ActiveSeatMemberIDs: []string{""}},
		"long seat id":      {TenantID: testOrg, ActiveSeatMemberIDs: []string{strings.Repeat("x", 129)}},
		"empty tenant":      {},
	} {
		if got := JudgeUsage(UsageEntry{Usage: u, PlacedHere: true}); got != UsageDropMalformed {
			t.Errorf("%s: JudgeUsage = %s, want malformed", name, got)
		}
	}
}
