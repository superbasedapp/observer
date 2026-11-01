//go:build !sbo_omit_security

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secframework"
)

// TestSecurityReportOnALegacyInstall (lane sec-h, the opt-in decision): an
// install with no [components] block gets the read-only report, which opens
// nothing; the opt-in controls read "not selected" (the feedback leaves
// AML.M0029 partial), the default-on ones "covered" (since the trust offer,
// P-044, that includes AML.T0081), and the explain verb refuses.
func TestSecurityReportOnALegacyInstall(t *testing.T) {
	cp := writeFeedbackConfig(t, "")
	cmd := newSecurityCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"report", "--config", cp, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Rows []secframework.Row `json:"rows"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	byID := map[string]secframework.Status{}
	for _, r := range got.Rows {
		byID[r.ID] = r.Status
	}
	if securityInertByDefault() {
		// The managed edition: with no block the module is inert, so every
		// control reads not selected.
		for id, st := range byID {
			if st != secframework.StatusNotSelected {
				t.Fatalf("%s reads %s on an install with no block in an edition that leaves the module inert: %v", id, st, byID)
			}
		}
		return
	}
	if byID["ASI02"] != secframework.StatusCovered || byID["AML.T0081"] != secframework.StatusCovered || byID["AML.M0029"] != secframework.StatusPartial {
		t.Fatalf("statuses: %v", byID)
	}
	out.Reset()
	cmd = newSecurityCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"report", "--config", cp, "--framework", "owasp-llm-2026"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "LLM03") || strings.Contains(out.String(), "ASI02") {
		t.Fatalf("text report:\n%s", out.String())
	}
	cmd = newSecurityCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"explain", "01ANY", "--config", cp})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "not selected") {
		t.Fatalf("explain on a legacy install: %v", err)
	}
}

// TestSecurityReportCompiledOutIsNotBuilt (audit finding 7): a component an
// omit tag compiled out of the binary reads not built, never built.
func TestSecurityReportCompiledOutIsNotBuilt(t *testing.T) {
	compiled := components.Compiled(components.BinaryNode)
	var without []string
	for _, id := range compiled {
		if id != securityFeedbackComponent {
			without = append(without, id)
		}
	}
	if len(without) == len(compiled) {
		t.Skip("security.feedback is not compiled into this build")
	}
	facts := securityFrameworkFacts(componentstate.Resolve(config.ComponentsConfig{}, without))
	if facts.Built(securityFeedbackComponent) {
		t.Fatal("a compiled-out security.feedback reads built")
	}
	if !facts.Built("security") {
		t.Fatal("the compiled security root reads not built")
	}
	if !securityFrameworkFacts(componentstate.Resolve(config.ComponentsConfig{}, compiled)).Built(securityFeedbackComponent) {
		t.Fatal("a compiled security.feedback reads not built")
	}
}
