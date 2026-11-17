//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// sandbox_setup_credential_test.go pins the setup panel's credential step:
// the run request carries the one key or each named field to the same
// keystore path the Hosted sandboxes panel uses, and the plan names the
// fields to ask for and the CLI form, so the dashboard can show a real input
// (it showed a "Turn on" button that sent no key and was refused).

// TestSandboxSetupHostedConnectFields: one row per request shape.
func TestSandboxSetupHostedConnectFields(t *testing.T) {
	cases := []struct {
		name    string
		backend string
		req     dashapi.SandboxSetupRunRequest
		want    map[string]string
		refused bool
	}{
		{"one key", sandboxbackend.BackendDaytona, dashapi.SandboxSetupRunRequest{Key: "k-1"}, map[string]string{"": "k-1"}, false},
		{"named fields", sandboxbackend.BackendModal, dashapi.SandboxSetupRunRequest{Fields: map[string]string{"MODAL_TOKEN_ID": "id", "MODAL_TOKEN_SECRET": "s"}}, map[string]string{"MODAL_TOKEN_ID": "id", "MODAL_TOKEN_SECRET": "s"}, false},
		{"nothing typed", sandboxbackend.BackendDaytona, dashapi.SandboxSetupRunRequest{}, nil, true},
		{"only spaces", sandboxbackend.BackendModal, dashapi.SandboxSetupRunRequest{Fields: map[string]string{"MODAL_TOKEN_ID": "  "}}, nil, true},
		{"a field with no name", sandboxbackend.BackendModal, dashapi.SandboxSetupRunRequest{Fields: map[string]string{"": "v"}}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newSetupRig(t, setupBaseConfig)
			_, err := runHostedConnect(context.Background(), runCtxFor(r, tc.backend, sandboxsetup.Step{Channel: sandboxsetup.ChHostedKey}, tc.req))
			if tc.refused {
				var se *sandboxSetupError
				if !errors.As(err, &se) || se.Code() != dashapi.SandboxSetupCodeStepNotRunnable {
					t.Fatalf("err = %v, want a step_not_runnable refusal", err)
				}
				if len(r.connected) != 0 {
					t.Fatalf("a refused request reached the keystore: %v", r.connected)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(r.connected, []string{tc.backend}) || !reflect.DeepEqual(r.connectedFields, []map[string]string{tc.want}) {
				t.Fatalf("connected %v with %v, want %s with %v", r.connected, r.connectedFields, tc.backend, tc.want)
			}
		})
	}
}

// TestSandboxSetupHostedConnectRefusalNamesNoValue: a keystore refusal is
// passed on by name; the typed value never appears in it.
func TestSandboxSetupHostedConnectRefusalNamesNoValue(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	const secret = "sk-very-secret-value-42"
	r.svc.run.hostedConnect = func(context.Context, string, map[string]string) error {
		return errors.New("MODAL_TOKEN_SECRET is required")
	}
	_, err := runHostedConnect(context.Background(), runCtxFor(r, sandboxbackend.BackendModal, sandboxsetup.Step{Channel: sandboxsetup.ChHostedKey},
		dashapi.SandboxSetupRunRequest{Fields: map[string]string{"MODAL_TOKEN_ID": secret}}))
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "MODAL_TOKEN_SECRET") {
		t.Fatalf("err = %v", err)
	}
}

// TestSandboxSetupCredentialStepExtras: every registry row whose setup has a
// credential step gets its provider's own field names and the CLI form; a
// provider whose calls carry a per-run token (the org-hosted row) gets
// neither, and no other step kind gets either.
func TestSandboxSetupCredentialStepExtras(t *testing.T) {
	seen := 0
	for _, id := range sandboxbackend.IDs() {
		c := mustRow(t, id)
		if !slices.Contains(c.Setup, "hosted-key") {
			continue
		}
		seen++
		v, ok := sandboxremote.VendorFor(c.ID)
		if !ok {
			t.Errorf("%s: a credential step on a row with no vendor", c.ID)
			continue
		}
		var w dashapi.SandboxSetupStep
		sandboxSetupStepExtras[sandboxsetup.KindCredential](c.ID, &w)
		if !reflect.DeepEqual(w.Fields, v.EnvCredential) || len(w.Fields) == 0 {
			t.Errorf("%s: fields %v, want %v", c.ID, w.Fields, v.EnvCredential)
		}
		if w.Command != "observer sandbox hosted connect "+c.ID {
			t.Errorf("%s: command %q", c.ID, w.Command)
		}
	}
	if seen == 0 {
		t.Fatal("no registry row has a credential step")
	}
	var org dashapi.SandboxSetupStep
	hostedCredentialStepExtras(sandboxbackend.BackendOpenShellOrg, &org)
	if org.Fields != nil || org.Command != "" {
		t.Errorf("the org-hosted row got credential extras: %+v", org)
	}
	for k := range sandboxSetupStepExtras {
		if k != sandboxsetup.KindCredential {
			t.Errorf("extras for kind %s: give it its own test row", k)
		}
	}
}

// TestSandboxSetupPlanWiresCredentialFields: the served plan of a hosted
// row names the key step's fields and command; a pm step's command display
// is flagged as a command.
func TestSandboxSetupPlanWiresCredentialFields(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	p := sandboxsetup.Build(sandboxsetup.PlanInput{
		Row: mustRow(t, sandboxbackend.BackendDaytona), Host: sandboxbackend.HostLinux, Family: sandboxsetup.FamilyDebian,
		OrgAllowed: true, ComponentID: "terminals.sandbox.daytona", ComponentSelected: true, AllowInstall: true,
	})
	w := r.svc.wire(context.Background(), sandboxSetupInput{}, p, false)
	var key *dashapi.SandboxSetupStep
	for i := range w.Steps {
		if w.Steps[i].Prereq == "hosted-key" {
			key = &w.Steps[i]
		}
	}
	if key == nil {
		t.Fatalf("no hosted-key step in %+v", w.Steps)
	}
	if !reflect.DeepEqual(key.Fields, []string{"DAYTONA_API_KEY"}) || key.Command != "observer sandbox hosted connect daytona" || key.DisplayIsCommand {
		t.Errorf("key step = %+v", key)
	}
	pb := sandboxsetup.Build(sandboxsetup.PlanInput{
		Row: mustRow(t, sandboxbackend.BackendBwrap), Host: sandboxbackend.HostLinux, Family: sandboxsetup.FamilyDebian,
		OrgAllowed: true, ComponentID: "terminals.sandbox", ComponentSelected: true, AllowInstall: true,
	})
	for _, st := range r.svc.wire(context.Background(), sandboxSetupInput{}, pb, false).Steps {
		if st.Prereq == "bwrap" && !st.DisplayIsCommand {
			t.Errorf("the bwrap pm step's display %q is not flagged as a command", st.Display)
		}
		if st.Fields != nil || st.Command != "" {
			t.Errorf("%s: credential extras on a local row", st.Prereq)
		}
	}
}

func mustRow(t *testing.T, id string) sandboxbackend.Capability {
	t.Helper()
	c, ok := sandboxbackend.Get(id)
	if !ok {
		t.Fatalf("no registry row %q", id)
	}
	return c
}
