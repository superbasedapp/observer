package scrub

import (
	"strings"
	"testing"
)

// TestSecretName walks the name table.
func TestSecretName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"--api-key", true},
		{"--token", true},
		{"-token", true},
		{"--client-secret", true},
		{"--password", true},
		{"--db-passwd", true},
		{"--aws-credential-file", true},
		{"OPENAI_API_KEY", true},
		{"Api_Key", true},
		{"--keymap", true}, // errs toward masking
		{"--model", false},
		{"--project", false},
		{"sandbox", false},
		{"", false},
	} {
		if got := SecretName(tc.name); got != tc.want {
			t.Errorf("SecretName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMaskSecretArgs pins the argument masking a confirm card uses.
func TestMaskSecretArgs(t *testing.T) {
	t.Parallel()
	ghp := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"joined", []string{"--api-key=sk-live-1"}, []string{"--api-key=" + Redacted}},
		{"next argument", []string{"--token", "t0k", "--model", "opus"}, []string{"--token", Redacted, "--model", "opus"}},
		{"after the separator", []string{"--", "--password", "hunter2"}, []string{"--", "--password", Redacted}},
		{"next is a flag", []string{"--token", "--model", "opus"}, []string{"--token", "--model", "opus"}},
		{"secret at the end", []string{"--secret"}, []string{"--secret"}},
		{"detected positional", []string{"--model", "opus", ghp}, []string{"--model", "opus", "[REDACTED:github_pat]"}},
		{"nothing secret", []string{"--model", "opus", "-p", "do it"}, []string{"--model", "opus", "-p", "do it"}},
		{"nil", nil, nil},
	} {
		got := MaskSecretArgs(tc.in)
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") || (got == nil) != (tc.want == nil) {
			t.Errorf("%s: MaskSecretArgs(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
	in := []string{"--api-key", "v"}
	_ = MaskSecretArgs(in)
	if in[1] != "v" {
		t.Fatal("MaskSecretArgs changed its input")
	}
}
