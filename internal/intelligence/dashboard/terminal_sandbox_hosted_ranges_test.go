package dashboard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestHostedPrivateRangesPayloadRoundTrip (SBXD-7): the GET shape carries the
// shared value, every deny-capable table's override (follow by default) and
// which tables can deny; a PUT applies what it sends, keeps what it leaves
// out, and refuses an unknown table or value.
func TestHostedPrivateRangesPayloadRoundTrip(t *testing.T) {
	saved := config.Default().Terminal.Sandbox.Hosted
	on := true
	saved.Vercel.AllowPrivateRanges = &on

	p := hostedPrivateRangesToPayload(saved)
	if p.AllowPrivateRanges == nil || *p.AllowPrivateRanges || (*p.Overrides)["vercel"] != "allow" || (*p.Overrides)["e2b"] != "follow" || len(p.DenyCapable) != len(config.HostedPrivateRangeDenyProviders) {
		t.Fatalf("payload %+v %v", p, *p.Overrides)
	}
	b, _ := json.Marshal(sandboxConfigPayload(config.TerminalSandboxConfig{Hosted: saved}).Hosted)
	for _, k := range []string{`"allow_private_ranges":false`, `"private_range_overrides"`, `"private_range_deny_capable"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("GET hosted block lacks %s: %s", k, b)
		}
	}

	// A body that sends the shared key and one override.
	next := saved
	next.Vercel = config.TerminalSandboxHostedProviderConfig{} // the provider table is rebuilt from the payload
	yes := true
	sent := hostedPrivateRangesPayload{AllowPrivateRanges: &yes, Overrides: &map[string]string{"e2b": "deny"}}
	if err := applyHostedPrivateRanges(&next, sent); err != nil {
		t.Fatal(err)
	}
	keepHostedPrivateRanges(&next, sent, saved)
	if !next.AllowPrivateRanges || next.E2B.AllowPrivateRanges == nil || *next.E2B.AllowPrivateRanges || next.Vercel.AllowPrivateRanges == nil || !*next.Vercel.AllowPrivateRanges {
		t.Fatalf("applied: shared %v e2b %v vercel %v", next.AllowPrivateRanges, next.E2B.AllowPrivateRanges, next.Vercel.AllowPrivateRanges)
	}

	// follow clears an override; a body with none of the block keeps all.
	cleared := saved
	if err := applyHostedPrivateRanges(&cleared, hostedPrivateRangesPayload{Overrides: &map[string]string{"vercel": "follow"}}); err != nil || cleared.Vercel.AllowPrivateRanges != nil {
		t.Errorf("follow: %v %v", err, cleared.Vercel.AllowPrivateRanges)
	}
	old := config.Default().Terminal.Sandbox.Hosted
	keepHostedPrivateRanges(&old, hostedPrivateRangesPayload{}, saved)
	if old.Vercel.AllowPrivateRanges == nil || !*old.Vercel.AllowPrivateRanges {
		t.Error("an older client's save dropped the saved override")
	}

	for _, bad := range []map[string]string{{"nosuch": "allow"}, {"e2b": "maybe"}} {
		c := saved
		if err := applyHostedPrivateRanges(&c, hostedPrivateRangesPayload{Overrides: &bad}); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestHostedPrivateRangesPutValidates: an override on a table whose vendor
// cannot deny is refused by the save's validation (a 400), never written.
func TestHostedPrivateRangesPutValidates(t *testing.T) {
	p := sandboxConfigPayload(config.Default().Terminal.Sandbox)
	p.Hosted.Overrides = &map[string]string{"modal": "allow"}
	if _, err := normalizedSandboxConfig(p); err == nil || !strings.Contains(err.Error(), "modal.allow_private_ranges") {
		t.Fatalf("an override with no effect: %v", err)
	}
	p.Hosted.Overrides = &map[string]string{"e2b": "allow"}
	got, err := normalizedSandboxConfig(p)
	if err != nil || got.Hosted.E2B.AllowPrivateRanges == nil || !*got.Hosted.E2B.AllowPrivateRanges {
		t.Fatalf("a valid override: %v %+v", err, got.Hosted.E2B)
	}
}
