package sandboxremote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// consentDigestV1 is the digest every record was made with before the
// in-box key fields existed (the ten fields of version 1).
func consentDigestV1(f ConsentFacts) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d", ConsentVersion)
	for _, kv := range [][2]string{
		{"provider", f.Provider},
		{"endpoint", f.Endpoint},
		{"region", f.Region},
		{"custody", f.Custody},
		{"tier", f.Tier},
		{"capture", f.Capture},
		{"scope", f.ScopeKey},
		{"box_binary", f.BoxBinary},
		{"memory_images", f.MemoryImages},
		{"cap", fmt.Sprintf("%d/%d", f.MaxRunMinutes, f.DailyBoxMinutes)},
	} {
		fmt.Fprintf(h, "\x00%s=%s", kv[0], kv[1])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestConsentInBoxKeyFields (decisions SBXD-3, SBXD-4): a record made
// before the fields existed still checks (empty adds nothing to the
// digest), and a change of each field reopens the consent naming it.
func TestConsentInBoxKeyFields(t *testing.T) {
	t.Parallel()
	f := ConsentFacts{Provider: "daytona", Endpoint: "https://app.daytona.io", Region: "us", Custody: "home_relay", Tier: "internet", Capture: "full", ScopeKey: "s", BoxBinary: "b", MemoryImages: "avoid", MaxRunMinutes: 60, DailyBoxMinutes: 240}
	if ConsentDigest(f) != consentDigestV1(f) {
		t.Fatal("a record made before the in-box key fields no longer checks")
	}
	old := ConsentRecord{Version: ConsentVersion, Facts: f, Digest: consentDigestV1(f)}
	if v := CheckConsent(&old, f); v != ConsentOK {
		t.Fatalf("old record = %s", v)
	}
	for _, tc := range []struct {
		field  string
		change func(*ConsentFacts)
	}{
		{"in_box_keys", func(f *ConsentFacts) { f.InBoxKeys = "openai" }},
		{"tool_keys", func(f *ConsentFacts) { f.ToolKeys = "opencode" }},
		{"login_seed", func(f *ConsentFacts) { f.LoginSeed = "claude-code" }},
	} {
		now := f
		tc.change(&now)
		if v := CheckConsent(&old, now); v != ConsentChangedPrefix+tc.field {
			t.Errorf("%s: %s", tc.field, v)
		}
		rec := NewConsent(now, "t")
		if v := CheckConsent(&rec, now); v != ConsentOK {
			t.Errorf("%s: a record with the field set = %s", tc.field, v)
		}
		if b, err := jsonRoundTrip(rec); err != nil || CheckConsent(&b, now) != ConsentOK {
			t.Errorf("%s: the record does not round-trip: %v", tc.field, err)
		}
	}
}

// jsonRoundTrip encodes rec and decodes it strictly, as the cmd layer
// stores and reads it.
func jsonRoundTrip(rec ConsentRecord) (ConsentRecord, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return ConsentRecord{}, err
	}
	return DecodeConsent(b)
}
