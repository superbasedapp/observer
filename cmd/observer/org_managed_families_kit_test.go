package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

var kitModuleFamilies = []string{policyfam.FamilySecurityScanning, policyfam.FamilyTerminalsIsolation}

// kitPreEnrolledManagedNode writes a managed node whose offered-families
// record was written by an older build's start: it offered every family that
// build governed (here, governedThen). It returns the config path and body.
func kitPreEnrolledManagedNode(t *testing.T, governedThen []string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	st := writeManagedFamiliesFixture(t, dbPath, orgcontract.TenancyManaged, govern.ConsentManaged, time.Now().Add(time.Hour))
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" + preFixManagedPolicy
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, ok, err := loadManagedPolicyFacts(context.Background(), st, time.Now())
	if err != nil || !ok {
		t.Fatalf("facts: %v %v", ok, err)
	}
	rec := managedFamiliesRecord{OrgKey: facts.OrgKey, Generation: facts.Generation, Offered: governedThen, UpdatedAt: "2026-10-01T00:00:00Z"}
	raw, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, managedFamiliesRecordName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, body
}

// withoutFamilies returns list minus drop.
func withoutFamilies(list []string, drop ...string) []string {
	var out []string
	for _, f := range list {
		if !hasFamily(drop, f) {
			out = append(out, f)
		}
	}
	return out
}

// TestAA64ModuleFamiliesWaitForALinkedCompiler is the audit SHR-KIT finding 1
// regression test: with neither module family's compiler linked (this build:
// the security and sandbox lanes add the pair files), an existing managed
// node's next start leaves config.toml byte for byte as it was, and neither
// family is offered at enrolment. An older binary that does not know the
// names, or an update rollback that restores the binary but not the config,
// therefore keeps loading it.
func TestAA64ModuleFamiliesWaitForALinkedCompiler(t *testing.T) {
	for _, f := range kitModuleFamilies {
		if policyfam.IsFamilyLinked(f) {
			t.Skipf("%s is linked in this build; TestAA64LinkedModuleFamilyIsBackfilledOnce covers it", f)
		}
	}
	governedNow := govern.ManagedGovernedFamilies(govern.ManagedEnrolmentAuthoritySet())
	for _, f := range kitModuleFamilies {
		if !hasFamily(governedNow, f) {
			t.Fatalf("govern no longer governs %s under managed consent; this test's premise moved", f)
		}
	}
	// The older build offered everything it governed, which excluded both.
	cfgPath, body := kitPreEnrolledManagedNode(t, withoutFamilies(governedNow, kitModuleFamilies...))
	var out bytes.Buffer
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &out)
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != body {
		t.Fatalf("a managed node's config.toml changed at start with no module compiler linked (output %q):\n%s", out.String(), after)
	}
	if out.Len() != 0 {
		t.Fatalf("start printed %q, want nothing", out.String())
	}
	if got := managedPolicyFamiliesToWrite(grantOutcome{Accepted: true, Managed: true, Authority: govern.ManagedEnrolmentAuthoritySet()}); hasFamily(got, kitModuleFamilies[0]) || hasFamily(got, kitModuleFamilies[1]) {
		t.Fatalf("the enrolment write offered an unlinked module family: %v", got)
	}
}

// TestAA64LinkedModuleFamilyIsBackfilledOnce: once a build links a module
// family's compiler (here a stand-in, swapped in for this test only), the
// pre-enrolled managed node gets that family, once, in both lists; the next
// start changes nothing; a developer who removes it keeps it removed; the
// family still unlinked is not offered; an individual node is untouched.
func TestAA64LinkedModuleFamilyIsBackfilledOnce(t *testing.T) {
	linked, unlinked := policyfam.FamilySecurityScanning, policyfam.FamilyTerminalsIsolation
	if policyfam.IsFamilyLinked(unlinked) {
		t.Skipf("%s is linked in this build; its own lane's test covers it", unlinked)
	}
	restore := policyfam.SwapLinkedFamilyForTest(linked, &policyfam.LinkedFamily{
		Compile:  func(raw []byte, _ int64) (any, []byte, error) { return nil, raw, nil },
		Enforces: func(any) bool { return false },
	})
	t.Cleanup(restore)
	governedNow := govern.ManagedGovernedFamilies(govern.ManagedEnrolmentAuthoritySet())
	cfgPath, _ := kitPreEnrolledManagedNode(t, withoutFamilies(governedNow, kitModuleFamilies...))

	var out bytes.Buffer
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &out)
	acc, pre := loadPolicyLists(t, cfgPath)
	if !hasFamily(acc, linked) || !hasFamily(pre, linked) {
		t.Fatalf("after start accept=%v preauth=%v, want %s (output %q)", acc, pre, linked, out.String())
	}
	if hasFamily(acc, unlinked) || hasFamily(pre, unlinked) {
		t.Fatalf("the unlinked %s was offered: accept=%v preauth=%v", unlinked, acc, pre)
	}
	count := 0
	for _, f := range acc {
		if f == linked {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%s listed %d times in %v", linked, count, acc)
	}

	// Idempotent: the next start leaves the file byte for byte.
	once, _ := os.ReadFile(cfgPath)
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &bytes.Buffer{})
	if twice, _ := os.ReadFile(cfgPath); string(twice) != string(once) {
		t.Fatalf("a second start rewrote the config:\n%s\nthen\n%s", once, twice)
	}

	// The developer removes it by hand; the next start does not put it back.
	// Remove it from whichever list holds it, first entry or not.
	trimmed := string(once)
	for _, spelling := range []string{`, "` + linked + `"`, `"` + linked + `", `, `"` + linked + `"`} {
		trimmed = strings.ReplaceAll(trimmed, spelling, "")
	}
	if err := os.WriteFile(cfgPath, []byte(trimmed), 0o600); err != nil {
		t.Fatal(err)
	}
	if acc, _ = loadPolicyLists(t, cfgPath); hasFamily(acc, linked) {
		t.Fatalf("test setup: removal did not take, %v", acc)
	}
	reconcileManagedPolicyAtStart(context.Background(), cfgPath, &bytes.Buffer{})
	if acc, _ = loadPolicyLists(t, cfgPath); hasFamily(acc, linked) {
		t.Fatalf("a removed family came back: %v", acc)
	}

	// An individual node with the same lists is never touched.
	idir := t.TempDir()
	idb := filepath.Join(idir, "observer.db")
	writeManagedFamiliesFixture(t, idb, orgcontract.TenancyIndividual, govern.ConsentInteractive, time.Now().Add(time.Hour))
	icfg := filepath.Join(idir, "config.toml")
	ibody := "[observer]\ndb_path = \"" + filepath.ToSlash(idb) + "\"\n" + preFixManagedPolicy
	if err := os.WriteFile(icfg, []byte(ibody), 0o600); err != nil {
		t.Fatal(err)
	}
	reconcileManagedPolicyAtStart(context.Background(), icfg, &bytes.Buffer{})
	if after, _ := os.ReadFile(icfg); string(after) != ibody {
		t.Fatalf("an individual node's config was rewritten:\n%s", after)
	}

	// The enrolment write offers the linked family and not the other.
	got := managedPolicyFamiliesToWrite(grantOutcome{Accepted: true, Managed: true, Authority: govern.ManagedEnrolmentAuthoritySet()})
	if !hasFamily(got, linked) || hasFamily(got, unlinked) {
		t.Fatalf("enrolment write %v, want %s and not %s", got, linked, unlinked)
	}
}
