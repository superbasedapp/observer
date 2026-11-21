package sandboxvocab

import (
	"strings"
	"testing"
)

func TestLadders(t *testing.T) {
	for i, c := range Classes() {
		if c.Rank() != i {
			t.Errorf("%s rank %d, want %d", c, c.Rank(), i)
		}
	}
	for i, c := range CaptureLevels() {
		if c.Rank() != i {
			t.Errorf("%s rank %d, want %d", c, c.Rank(), i)
		}
	}
	for i, tr := range Tiers() {
		if tr.Strictness() != i {
			t.Errorf("%s strictness %d, want %d", tr, tr.Strictness(), i)
		}
	}
	if IsoClass("vm").Valid() || CaptureLevel("").Valid() || Tier("open").Valid() {
		t.Error("an unknown value is valid")
	}
}

func TestMinCapture(t *testing.T) {
	for _, tc := range []struct{ a, b, want CaptureLevel }{
		{CaptureFull, CaptureProxyAndTranscripts, CaptureProxyAndTranscripts},
		{CaptureTranscriptsOnly, CaptureFull, CaptureTranscriptsOnly},
		{CaptureFull, CaptureFull, CaptureFull},
		{CaptureFull, "bogus", CaptureNone},
	} {
		if got := MinCapture(tc.a, tc.b); got != tc.want {
			t.Errorf("MinCapture(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestClassSourceForFloors(t *testing.T) {
	if !SourceMeasured.CountsForFloor() || !SourceDocumented.CountsForFloor() || SourceClaimed.CountsForFloor() || ClassSource("").CountsForFloor() {
		t.Error("claimed or unknown counts for a floor")
	}
	if VerifiedLive.IsBeta() || !VerifiedDoc.IsBeta() || !Verification("").IsBeta() {
		t.Error("beta label wrong")
	}
}

func TestMatchesHost(t *testing.T) {
	hosts := []string{"api.anthropic.com", "openrouter.ai"}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"API.Anthropic.COM.", true},
		{"eu.api.anthropic.com", true},
		{"notapi.anthropic.com", false},
		{"anthropic.com", false},
		{"openrouter.ai", true},
		{"evilopenrouter.ai", false},
		{"", false},
	} {
		if got := MatchesHost(tc.host, hosts); got != tc.want {
			t.Errorf("MatchesHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	for _, h := range ModelProviderHosts() {
		if !MatchesHost(h, ModelProviderHosts()) {
			t.Errorf("%s does not match itself", h)
		}
	}
}

// TestDedicatedAddressHostsLeaveSharedFrontEndsOut pins audit finding
// P-006 (1): no host on a shared Google or Cloudflare front end feeds the
// address rule, and every dedicated host is also a name-blocked host.
func TestDedicatedAddressHostsLeaveSharedFrontEndsOut(t *testing.T) {
	shared := []string{"chatgpt.com", "openrouter.ai", "api.groq.com", "api.together.xyz", "api.openai.com"}
	for _, h := range DedicatedAddressHosts() {
		if strings.HasSuffix(h, "googleapis.com") || MatchesHost(h, shared) {
			t.Errorf("%s sits on a shared front end and must not feed the address rule", h)
		}
		if !MatchesHost(h, ModelProviderHosts()) {
			t.Errorf("dedicated host %s is not in the name list", h)
		}
	}
	for _, h := range []string{"proxy.golang.org", "storage.googleapis.com", "oauth2.googleapis.com", "registry.npmjs.org"} {
		if MatchesHost(h, ModelProviderHosts()) {
			t.Errorf("%s is refused by name", h)
		}
	}
}

func TestProviderDirectVocabulary(t *testing.T) {
	for _, tc := range []struct {
		in    ProviderDirect
		valid bool
		norm  ProviderDirect
	}{
		{ProviderDirectRefuseAll, true, ProviderDirectRefuseAll},
		{ProviderDirectCaptureRule, true, ProviderDirectCaptureRule},
		{ProviderDirectAllow, true, ProviderDirectAllow},
		{"", false, ProviderDirectCaptureRule},
		{"block", false, ProviderDirectCaptureRule},
	} {
		if got := tc.in.Valid(); got != tc.valid {
			t.Errorf("%q.Valid() = %v", tc.in, got)
		}
		if got := tc.in.Normalize(); got != tc.norm {
			t.Errorf("%q.Normalize() = %q", tc.in, got)
		}
	}
}

func TestSeccompVocabulary(t *testing.T) {
	t.Parallel()
	for _, s := range []Seccomp{SeccompNone, SeccompEngineDefault, SeccompObserverProfile} {
		if !s.Valid() {
			t.Errorf("%q is not valid", s)
		}
	}
	for _, s := range []Seccomp{"", "baseline", "Observer_profile"} {
		if s.Valid() {
			t.Errorf("%q is valid", s)
		}
	}
}
