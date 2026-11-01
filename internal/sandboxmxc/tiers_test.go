package sandboxmxc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func probeOut(tier string, dacl bool) ProbeOutput {
	return ProbeOutput{Tier: tier, NeedsDaclAugmentation: &dacl, Warnings: []string{}}
}

// TestTierVerdictPerRow: mxc-process keeps exactly base-container,
// mxc-appcontainer exactly appcontainer-bfs, and the DACL tier is refused
// on both.
func TestTierVerdictPerRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		row, tier string
		dacl      bool
		ok        bool
	}{
		{RowMXCProcess, TierBaseContainer, false, true},
		{RowMXCProcess, TierAppContainerBFS, false, false},
		{RowMXCProcess, TierAppContainerDACL, true, false},
		{RowMXCAppContainer, TierAppContainerBFS, false, true},
		{RowMXCAppContainer, TierAppContainerBFS, true, false},
		{RowMXCAppContainer, TierBaseContainer, false, false},
		{RowMXCAppContainer, TierAppContainerDACL, true, false},
		{RowMXCAppContainer, "", false, false},
	}
	for _, c := range cases {
		v := TierVerdict(c.row, probeOut(c.tier, c.dacl))
		if v.OK() != c.ok || (!c.ok && v.Reason == "") {
			t.Errorf("%s/%s dacl=%v: %+v", c.row, c.tier, c.dacl, v)
		}
	}
	if got := AcceptedTiers(RowMXCProcess); len(got) != 1 || got[0] != TierBaseContainer {
		t.Fatalf("mxc-process accepts %v", got)
	}
}

// TestMXCProcessProbeGolden: the mxc-process probe ladder and document are
// byte-identical to before lane GATES-SBX (a digest of their output on the
// recorded answers; tiers.go adds and changes nothing there).
func TestMXCProcessProbeGolden(t *testing.T) {
	t.Parallel()
	var out []any
	for _, json1 := range []string{
		`{"tier":"base-container","needsDaclAugmentation":false,"warnings":[],"probes":{"baseContainerApiPresent":true,"baseContainerSupportsDenyPaths":true,"baseContainerSupportsIngressHostLoopbackAllow":true,"baseContainerSupportsIdentitylessLoopbackProxy":true,"uiCapabilities":{}}}`,
		`{"tier":"appcontainer-bfs","needsDaclAugmentation":false,"warnings":["no PSEC"],"probes":{}}`,
		`{"tier":"appcontainer-dacl","needsDaclAugmentation":true,"warnings":["no BaseContainer"],"probes":{}}`,
	} {
		f := goodFacts()
		f.ProbeJSON = json1
		out = append(out, Probe(f, ManifestX64))
	}
	doc, err := ProbeDocument(`C:\Windows\System32\cmd.exe`, `C:\Windows`, `C:\Users\u\AppData\Local`)
	out = append(out, doc, err == nil)
	b, _ := json.Marshal(out)
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != mxcProcessGolden {
		t.Fatalf("the mxc-process probe or document changed: digest %s (was %s); a change there is not lane GATES-SBX's", got, mxcProcessGolden)
	}
}

// TestTierPinEnumReview fails when a value is added without a direction
// review: the pin is restrictive-only (an org may set only the safe value),
// and the weaker value is labelled weaker than ProcessContainer.
func TestTierPinEnumReview(t *testing.T) {
	t.Parallel()
	reviewed := map[TierPin]bool{PinProcessContainer: true, PinAppContainer: false}
	if len(TierPinValues) != len(reviewed) {
		t.Fatalf("windows.mxc_tier has %d values; review the direction of the new one and add it here", len(TierPinValues))
	}
	for _, v := range TierPinValues {
		accepted, ok := reviewed[v.Value]
		if !ok || OrgPinAccepted(v.Value) != accepted {
			t.Fatalf("%s: org pin accepted = %v, reviewed %v", v.Value, OrgPinAccepted(v.Value), accepted)
		}
	}
	if TierPinValues[0].Value != PinSafe || TierPinValues[0].Rank <= TierPinValues[1].Rank {
		t.Fatal("the safe value must be the strongest")
	}
	if PinAllowsRow(PinProcessContainer, RowMXCAppContainer) || !PinAllowsRow("", RowMXCAppContainer) || !PinAllowsRow(PinProcessContainer, RowMXCProcess) {
		t.Fatal("PinAllowsRow")
	}
}
