package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// TestTenantContextKeyFromEnv: one case per input shape. Not parallel: each
// case sets the process environment (t.Setenv).
func TestTenantContextKeyFromEnv(t *testing.T) {
	good := strings.Repeat("5a", 32)
	file := filepath.Join(t.TempDir(), "tenant-context-key")
	if err := os.WriteFile(file, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, value, file string
		want              []byte
		invalid, fails    bool
	}{
		{name: "unset"},
		{name: "env", value: good, want: bytes.Repeat([]byte{0x5a}, 32)},
		{name: "file", file: file, want: bytes.Repeat([]byte{0x5a}, 32)},
		{name: "env wins over file", value: strings.Repeat("a5", 32), file: file, want: bytes.Repeat([]byte{0xa5}, 32)},
		{name: "not hex", value: strings.Repeat("zz", 32), fails: true},
		{name: "too short", value: strings.Repeat("5a", 31), invalid: true, fails: true},
		{name: "missing file", file: filepath.Join(t.TempDir(), "absent"), fails: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(envTenantContextKey, c.value)
			t.Setenv(envTenantContextKeyFile, c.file)
			got, err := tenantContextKeyFromEnv()
			if (err != nil) != c.fails || (c.invalid && !errors.Is(err, tenantctx.ErrInvalidContext)) {
				t.Fatalf("err = %v", err)
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("key = %x, want %x", got, c.want)
			}
		})
	}
}

// TestKeyLogDecision: migrate sends the key only when no logging rule
// applies, or when the operator accepted the exposure with exactly "1".
func TestKeyLogDecision(t *testing.T) {
	t.Parallel()
	ovh := tenantctx.KeyLogExposure(map[string]string{"log_min_duration_statement": "1000", "log_parameter_max_length": "-1"})
	if len(ovh) == 0 {
		t.Fatal("OVH's slow-statement logging is not an exposure")
	}
	cases := []struct {
		name    string
		reasons []string
		allow   string
		refuse  bool
	}{
		{"no exposure", nil, "", false},
		{"no exposure, override set", nil, "1", false},
		{"exposure refused", ovh, "", true},
		{"exposure, override not 1", ovh, "yes", true},
		{"exposure accepted", ovh, "1", false},
	}
	for _, c := range cases {
		err := keyLogDecision(c.reasons, c.allow)
		if (err != nil) != c.refuse {
			t.Errorf("%s: err = %v, want refuse=%v", c.name, err, c.refuse)
		}
		if err != nil && !strings.Contains(err.Error(), envAllowKeyInDBLog) {
			t.Errorf("%s: refusal %q does not name %s", c.name, err, envAllowKeyInDBLog)
		}
	}
}
