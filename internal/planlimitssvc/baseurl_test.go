package planlimitssvc

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
)

// TestSaveChecksGatewayBaseURL: a self-hosted gateway account is saved only
// with a base URL the egress policy would accept (ledger SUBS-5), so an
// account that could never be polled is never stored.
func TestSaveChecksGatewayBaseURL(t *testing.T) {
	src, ok := planlimits.SourceByID(planlimits.SourceLiteLLMGateway)
	if !ok || !src.UserBaseURL {
		t.Fatal("litellm gateway source missing")
	}
	secrets := map[string]string{"key": "K"}
	cases := []struct {
		base string
		ok   bool
	}{
		{"https://litellm.example.com", true},
		{"https://litellm.example.com:4443/proxy", true},
		{"http://127.0.0.1:4000", true},
		{"http://localhost:4000/v1", true},
		{"http://[::1]:4000", true},
		{"", false},
		{"http://litellm.example.com", false},
		{"http://10.0.0.8:4000", false},
		{"https://u:p@litellm.example.com", false},
		{"https://litellm.example.com/?team=1", false},
		{"https://litellm.example.com/#x", false},
		{"ftp://litellm.example.com", false},
		{"litellm.example.com", false},
	}
	for _, c := range cases {
		err := validate(src, map[string]string{planlimits.ParamBaseURL: c.base}, secrets, true)
		if (err == nil) != c.ok {
			t.Errorf("base %q: err=%v, want ok=%v", c.base, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("base %q: %v is not ErrInvalid", c.base, err)
		}
	}
	// A fixed-host source never takes a base URL at all.
	fixed, _ := planlimits.SourceByID(planlimits.SourceOpenRouter)
	if err := validate(fixed, map[string]string{planlimits.ParamBaseURL: "https://x.example.com"}, map[string]string{"key": "K"}, true); err == nil {
		t.Error("a fixed-host source must refuse a base URL")
	}
}
