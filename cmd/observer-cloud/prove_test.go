package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/prove"
)

// TestProveCommandNeverReadsTheWorkerCredential is the CLI half of the W3a
// credential-separation property (review finding 4). The proving lane is
// operator-authenticated and pinned to its OWN credential variable: the
// subcommand's source must never name the production worker's credential
// variable or its chooser, so a proving run cannot borrow — or weaken — the
// worker's credential-ABSENCE boundary.
func TestProveCommandNeverReadsTheWorkerCredential(t *testing.T) {
	src, err := os.ReadFile("prove.go")
	if err != nil {
		t.Fatalf("read prove.go: %v", err)
	}
	text := string(src)
	// Reassembled at runtime so this assertion does not itself plant the string
	// the scan forbids.
	workerVar := "SBCI_" + "FOUNDRY_API_KEY"
	for _, bad := range []string{workerVar, "chooseCredentials", "AbsentCredentials", "StaticCredentials"} {
		if strings.Contains(text, bad) {
			t.Fatalf("cmd/observer-cloud/prove.go references %q — the proving lane must use only its own "+
				"credential (%s); the worker's absence boundary stays untouched", bad, envProveFoundryAPIKey)
		}
	}
	if !strings.Contains(text, envProveFoundryAPIKey) {
		t.Fatalf("prove.go no longer reads %s — the lane would have no credential of its own", envProveFoundryAPIKey)
	}
	// And the constant itself is the prove variable, not the worker's.
	if envProveFoundryAPIKey == workerVar {
		t.Fatal("the prove-lane credential variable collided with the worker's")
	}
}

// TestProveCommandRefusesWithoutItsCredential pins deliverable 2's honest
// refusal: with no prove-lane key the subcommand fails, names the variable to
// set, and never opens the database or reaches a provider.
func TestProveCommandRefusesWithoutItsCredential(t *testing.T) {
	t.Setenv(envProveFoundryAPIKey, "")
	t.Setenv(envProveRoute, "session_enrichment.luna.v1")
	// A DSN that would fail loudly if the command got as far as opening a store.
	t.Setenv("SBCI_PG_DSN", "postgres://invalid:1/none?sslmode=disable")

	cmd := newProveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("prove ran without a prove-lane credential")
	}
	if !strings.Contains(err.Error(), envProveFoundryAPIKey) {
		t.Fatalf("the refusal must name the variable to set: %v", err)
	}
	if strings.Contains(err.Error(), "SBCI_PG_DSN") || strings.Contains(err.Error(), "connect") {
		t.Fatalf("the credential check must run BEFORE the database is opened: %v", err)
	}
}

// TestProveCommandRefusesWithoutARoute pins that the lane never guesses which
// route to spend a provider call against.
func TestProveCommandRefusesWithoutARoute(t *testing.T) {
	t.Setenv(envProveFoundryAPIKey, "a-prove-key")
	t.Setenv(envProveRoute, "")

	cmd := newProveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("prove ran with no route selected")
	}
	if !strings.Contains(err.Error(), envProveRoute) {
		t.Fatalf("the refusal must name %s: %v", envProveRoute, err)
	}
}

// TestProveCommandListsTheCompiledInCatalog pins that --list is a pure,
// offline description of what is in the binary: no credential, no DSN, no
// provider call. It is how an operator inspects the lane before running it.
func TestProveCommandListsTheCompiledInCatalog(t *testing.T) {
	t.Setenv(envProveFoundryAPIKey, "")
	t.Setenv(envProveRoute, "")
	t.Setenv("SBCI_PG_DSN", "")

	cmd := newProveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("prove --list: %v", err)
	}
	text := out.String()
	for _, f := range prove.Catalog() {
		if !strings.Contains(text, f.Name) {
			t.Fatalf("--list omitted fixture %q:\n%s", f.Name, text)
		}
	}
	if !strings.Contains(text, "accepted from a client") {
		t.Fatalf("--list must state the compiled-in provenance:\n%s", text)
	}
}

// TestSelectFixtures pins the closed catalog: a named fixture resolves, and an
// unknown name is an error that lists what exists rather than silently running
// everything.
func TestSelectFixtures(t *testing.T) {
	all, err := selectFixtures("")
	if err != nil || len(all) != len(prove.Catalog()) {
		t.Fatalf("empty selector = %d fixtures, err %v; want the whole catalog", len(all), err)
	}
	one, err := selectFixtures("structural_only")
	if err != nil || len(one) != 1 || one[0].Name != "structural_only" {
		t.Fatalf("named selector = %+v, err %v", one, err)
	}
	_, err = selectFixtures("evidence-from-a-client")
	if err == nil {
		t.Fatal("an unknown fixture name was accepted — the catalog is closed")
	}
	for _, f := range prove.Catalog() {
		if !strings.Contains(err.Error(), f.Name) {
			t.Fatalf("the error must list the available catalog, missing %q: %v", f.Name, err)
		}
	}
}

// TestProveEnvVarsAreDistinctFromTheWorkers pins that no prove-lane variable
// name collides with a production worker variable.
func TestProveEnvVarsAreDistinctFromTheWorkers(t *testing.T) {
	workerVars := map[string]bool{
		"SBCI_" + "FOUNDRY_API_KEY": true,
		"SBCI_WORKER_ID":            true,
	}
	for _, v := range []string{envProveFoundryAPIKey, envProveRoute, envProveARMToken, envProveARMBaseURL, envProveARMAPIVersion} {
		if workerVars[v] {
			t.Fatalf("prove-lane variable %q collides with a production worker variable", v)
		}
		if !strings.HasPrefix(v, "SBCI_PROVE_") {
			t.Fatalf("prove-lane variable %q is not namespaced SBCI_PROVE_*", v)
		}
	}
}

// TestEnvOrPrefersTheProveVariable pins the ARM-token fallback order: the
// prove-lane variable wins, and the production ARM READER token is only a
// fallback (an ARM reader token is not a provider credential, so sharing it
// does not touch the absence boundary).
func TestEnvOrPrefersTheProveVariable(t *testing.T) {
	t.Setenv(envProveARMToken, "  prove-token  ")
	t.Setenv("SBCI_ARM_TOKEN", "shared-token")
	if got := envOr(envProveARMToken, "SBCI_ARM_TOKEN"); got != "prove-token" {
		t.Fatalf("envOr = %q, want the trimmed prove-lane value", got)
	}
	t.Setenv(envProveARMToken, "")
	if got := envOr(envProveARMToken, "SBCI_ARM_TOKEN"); got != "shared-token" {
		t.Fatalf("envOr = %q, want the fallback", got)
	}
	t.Setenv("SBCI_ARM_TOKEN", "")
	if got := envOr(envProveARMToken, "SBCI_ARM_TOKEN"); got != "" {
		t.Fatalf("envOr = %q, want empty (which makes the attestation fail closed)", got)
	}
}

// TestProveIsRegisteredAsASubcommand pins that the verb is actually reachable.
func TestProveIsRegisteredAsASubcommand(t *testing.T) {
	for _, c := range newRootCmd().Commands() {
		if c.Name() == "prove" {
			return
		}
	}
	t.Fatal("observer-cloud has no `prove` subcommand registered")
}
