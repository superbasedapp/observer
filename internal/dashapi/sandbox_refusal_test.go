package dashapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSandboxRefusalText: a surface shows a step refusal's plain sentence
// (the live-run report 2026-11-18: a clone URL with a user name showed
// "terminal_sandbox: clone_url_invalid: ... (workspace.Validate...)"), and
// any other error as before.
func TestSandboxRefusalText(t *testing.T) {
	step := &SandboxStepRefusal{Code: "clone_url_invalid", Message: "The remote URL cannot be cloned in the box.", Technical: "workspace.ValidateBoxCloneURL: it carries a user name"}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"a step refusal", step, step.Message},
		{"a wrapped step refusal", fmt.Errorf("prepare: %w", step), step.Message},
		{"an empty sentence keeps the error", &SandboxStepRefusal{Code: "x", Message: " "}, "terminal_sandbox: x:  "},
		{"any other error", errors.New("region unknown"), "region unknown"},
	}
	for _, c := range cases {
		if got := SandboxRefusalText(c.err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSandboxConsentRefusal: the typed hosted consent refusal keeps the
// sentence a CLI and the logs printed before it existed.
func TestSandboxConsentRefusal(t *testing.T) {
	e := &SandboxConsentRefusal{Provider: "daytona", Verdict: "consent_changed_scope"}
	want := "terminal_sandbox: consent_required (consent_changed_scope): review what leaves this machine and agree in Terminals > Settings > Hosted sandboxes, or run `observer sandbox hosted consent daytona`"
	if e.Error() != want {
		t.Fatalf("Error() = %q", e.Error())
	}
	var got *SandboxConsentRefusal
	if !errors.As(fmt.Errorf("termsvc: %w", e), &got) || got.Verdict != "consent_changed_scope" || !strings.HasPrefix(e.Error(), "terminal_sandbox: "+SandboxConsentRefusalCode) {
		t.Fatalf("unwrap: %+v", got)
	}
}
