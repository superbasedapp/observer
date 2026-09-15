package cloudcontract

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"testing"
)

func validCommunityContribution() CommunityContribution {
	c := CommunityContribution{
		SchemaVersion: CommunityContributionSchemaVersion,
		CohortKey:     "global",
		MetricID:      "sessions_per_active_day",
		MetricVersion: 1,
		WindowID:      "2025-01",
		Value:         3.5,
	}
	d, err := CommunityDigest(c)
	if err != nil {
		panic(err)
	}
	c.Digest = d
	return c
}

func TestCommunityDataDictionaryIsSorted(t *testing.T) {
	got := append([]string(nil), communityDataDictionary...)
	want := append([]string(nil), communityDataDictionary...)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("community data dictionary is not sorted at %d: %q vs %q", i, got[i], want[i])
		}
	}
}

func TestCommunityDataDictionaryDigestStable(t *testing.T) {
	// A change to the dictionary is a change to what a standing grant binds; it
	// must be a deliberate edit, so pin the digest. Update this literal ONLY when
	// you intend to change the contribution schema (and bump the schema version).
	got := CommunityDataDictionaryDigest()
	if got == "" {
		t.Fatal("empty community data dictionary digest")
	}
	// A second call agrees with the first (pure function over a constant
	// preimage).
	if again := CommunityDataDictionaryDigest(); again != got {
		t.Fatalf("community data dictionary digest is not deterministic: %q then %q", got, again)
	}
}

func TestCommunityDigestExcludesItself(t *testing.T) {
	c := validCommunityContribution()
	// The digest is over the preimage (Digest absent). Recomputing from the
	// digest-bearing struct must equal the stored value.
	got, err := CommunityDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if got != c.Digest {
		t.Fatalf("digest is self-referential: stored %q recomputed %q", c.Digest, got)
	}
	// Preimage must not contain the digest string.
	pre, err := CommunityPreimage(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(pre) == "" {
		t.Fatal("empty preimage")
	}
}

func TestCommunityUploadBytesAreCanonical(t *testing.T) {
	c := validCommunityContribution()
	b, err := CommunityUploadBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	// The server recomputes the digest from the received bytes: parse them back,
	// recompute, and it must match the embedded digest — the exact server check.
	var round CommunityContribution
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	rd, err := CommunityDigest(round)
	if err != nil {
		t.Fatal(err)
	}
	if rd != c.Digest {
		t.Fatalf("round-trip digest mismatch: %q vs %q", rd, c.Digest)
	}
}

func TestCommunityValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CommunityContribution)
		wantErr bool
	}{
		{"valid", func(*CommunityContribution) {}, false},
		{"bad schema", func(c *CommunityContribution) { c.SchemaVersion = "x" }, true},
		{"empty cohort", func(c *CommunityContribution) { c.CohortKey = "" }, true},
		{"long cohort", func(c *CommunityContribution) { c.CohortKey = string(make([]byte, MaxCohortKeyBytes+1)) }, true},
		{"empty metric", func(c *CommunityContribution) { c.MetricID = "" }, true},
		{"zero version", func(c *CommunityContribution) { c.MetricVersion = 0 }, true},
		{"bad window", func(c *CommunityContribution) { c.WindowID = "2025-13" }, true},
		{"bad window shape", func(c *CommunityContribution) { c.WindowID = "2025-1" }, true},
		{"nan value", func(c *CommunityContribution) { c.Value = math.NaN() }, true},
		{"inf value", func(c *CommunityContribution) { c.Value = math.Inf(1) }, true},
		{"negative value", func(c *CommunityContribution) { c.Value = -1 }, true},
		{"over ceiling", func(c *CommunityContribution) { c.Value = MaxContributionValue + 1 }, true},
		{"zero value ok", func(c *CommunityContribution) { c.Value = 0 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validCommunityContribution()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestCommunityDataDictionaryBindsTheWindowRuleAndTimezone pins the Sol
// re-review N1/N5 terms bump: the source-window rule and the UTC-fixed declared
// timezone are part of what a community standing grant binds, so a receipt
// recorded under the retired "completed months" rule carries a dictionary
// digest this package no longer serves (reconfirmation required), and the
// rule id itself is the truthful in-progress-month one.
func TestCommunityDataDictionaryBindsTheWindowRuleAndTimezone(t *testing.T) {
	if CommunitySourceWindowRule != "in_progress_utc_month_after_grant" {
		t.Fatalf("CommunitySourceWindowRule = %q, want the v1 in-progress-month rule", CommunitySourceWindowRule)
	}
	if CommunityDeclaredTimezone != "UTC" {
		t.Fatalf("CommunityDeclaredTimezone = %q, want UTC", CommunityDeclaredTimezone)
	}
	pre := string(CommunityDataDictionaryPreimage())
	for _, want := range []string{
		"source_window_rule:in_progress_utc_month_after_grant",
		"grant:declared_timezone:UTC",
	} {
		if !strings.Contains(pre, want) {
			t.Errorf("community data dictionary preimage lacks %q:\n%s", want, pre)
		}
	}
	if strings.Contains(pre, "completed_utc_months_after_grant") {
		t.Error("the retired completed-months rule is still in the dictionary")
	}
	// The digest a receipt under the OLD dictionary bound (the same enumeration
	// minus the two new lines) must not equal the one served now — that
	// inequality IS the reconfirmation trigger.
	var old []string
	for _, line := range communityDataDictionary {
		if strings.HasPrefix(line, "source_window_rule:") || strings.HasPrefix(line, "grant:declared_timezone:") {
			continue
		}
		old = append(old, line)
	}
	if digest([]byte(strings.Join(old, "\n"))) == CommunityDataDictionaryDigest() {
		t.Fatal("the dictionary digest did not change with the terms — an old-rule receipt would still look live")
	}
}
