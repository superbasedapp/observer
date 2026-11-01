//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_scan_consent_sign_test.go is the lane sec-deps4 audit's
// follow-ups on the consent records: a hand-written record is not the
// developer's consent (finding 1), `scan --online` is not held back by
// the database accept (finding 2), and a managed node never waits for an
// accept it cannot give (finding 3).

// testDepsSigningKey is the key the accept paths sign with, for a test
// that records consent directly.
func testDepsSigningKey(t *testing.T, dir string) []byte {
	t.Helper()
	key, err := depsRecordSigningKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestHandWrittenConsentRecordsDoNotCount: an agent's own
// osv-db-consent.json and online-disclosure.json (the unsigned shape an
// older plan-branch build also wrote) read not accepted and not shown, so
// nothing downloads and no scan claims anything; the real accept paths
// still record a consent that reads back.
func TestHandWrittenConsentRecordsDoNotCount(t *testing.T) {
	remote := useRemote(t)
	cfgPath, secDir := scanConsentConfig(t)
	ctx := context.Background()
	if err := os.MkdirAll(secDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A posture key exists (a daemon ran), so the only thing missing is
	// the record's own MAC.
	testDepsSigningKey(t, secDir)
	for name, body := range map[string]string{
		osvdb.ConsentFile:  `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli"}`,
		depsDisclosureFile: `{"version":2,"shown_at":"2026-10-21T09:00:00Z","surface":"cli"}`,
	} {
		if err := os.WriteFile(filepath.Join(secDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	if e.consent.Accepted() || e.downloadBlocked() != depscan.ReasonDBNotAccepted {
		t.Fatalf("a hand-written accept counts: %+v, blocked %q", e.consent, e.downloadBlocked())
	}
	if readDepsDisclosure(secDir).Shown() {
		t.Fatal("a hand-written disclosure counts")
	}
	var lastDB time.Time
	if err := depsScanPass(ctx, cfgPath, depscan.OSVComponent, &lastDB); err != nil {
		t.Fatal(err)
	}
	if remote.calls.Load() != 0 {
		t.Fatal("a hand-written accept started the download")
	}
	d := &countingDriver{}
	res, err := e.scanOne(ctx, d, t.TempDir(), secscan.Target{Scope: policy.FindingScopeManual}, false, nil, false)
	if err != nil || d.scans != 0 || res.Coverage.Reason != depscan.ReasonDBNotAccepted {
		t.Fatalf("scan after a hand-written accept: %+v %v (scans %d)", res.Coverage, err, d.scans)
	}

	// The real accept paths overwrite the files with signed records.
	var out bytes.Buffer
	if err := runDBAccept(&out, strings.NewReader(""), e, true, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatalf("the CLI accept does not read back:\n%s", out.String())
	}
	if _, err := recordDepsDisclosure(secDir, "cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !readDepsDisclosure(secDir).Shown() {
		t.Fatal("the recorded disclosure does not read back")
	}
	again, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(again.cleanup)
	if !again.consent.Accepted() || again.downloadBlocked() != "" {
		t.Fatalf("after the accept: %+v, blocked %q", again.consent, again.downloadBlocked())
	}
}

// TestConsentRecordWithoutKeyFile: a record signed under a key that was
// since replaced (or one read with no key on disk) reads not accepted.
func TestConsentRecordWithoutKeyFile(t *testing.T) {
	_, secDir := scanConsentConfig(t)
	if _, err := osvdb.RecordConsent(secDir, "cli", "dev", time.Now(), testDepsSigningKey(t, secDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(depsRecordKeyPath(secDir)); err != nil {
		t.Fatal(err)
	}
	if osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatal("a record reads accepted with its key gone")
	}
	testDepsSigningKey(t, secDir) // a fresh key
	if osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatal("a record reads accepted under a new key")
	}
}

// TestScanOnlineSkipsTheAcceptWait is audit finding 2: with an online
// matcher attached and the online gate open, a scan with no database and
// no accept runs (the matcher covers what the local database cannot);
// without the matcher, or with the gate closed, it still waits.
func TestScanOnlineSkipsTheAcceptWait(t *testing.T) {
	useRemote(t)
	cfgPath, secDir := scanConsentConfig(t)
	ctx := context.Background()
	e, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	if _, err := recordDepsDisclosure(secDir, "cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	e.disclose = readDepsDisclosure(secDir)
	e.cfg.Security.Deps.Online = true
	if e.onlineBlocked() != "" || !e.awaitingAccept() {
		t.Fatalf("setup: online %q, awaiting %v", e.onlineBlocked(), e.awaitingAccept())
	}
	scan := func(online bool) (int, secscan.Result) {
		d := &countingDriver{}
		res, err := e.scanOne(ctx, d, t.TempDir(), secscan.Target{Scope: policy.FindingScopeManual}, false, nil, online)
		if err != nil {
			t.Fatal(err)
		}
		return d.scans, res
	}
	if n, res := scan(true); n != 1 || res.Coverage.Reason == depscan.ReasonDBNotAccepted {
		t.Fatalf("--online with the gate open was held back: scans %d, %+v", n, res.Coverage)
	}
	if n, res := scan(false); n != 0 || res.Coverage.Reason != depscan.ReasonDBNotAccepted {
		t.Fatalf("a local scan ran before the accept: scans %d, %+v", n, res.Coverage)
	}
	e.cfg.Security.Deps.Online = false
	if n, _ := scan(true); n != 0 {
		t.Fatal("a matcher with the online gate closed skipped the accept")
	}
	var m depdriver.OnlineMatcher = func(context.Context, string, []depscan.Package, []int) (depscan.EcoResult, bool) {
		return depscan.EcoResult{}, false
	}
	for _, c := range []struct {
		component string
		m         depdriver.OnlineMatcher
		want      bool
	}{
		{depscan.ScalibrComponent, m, true},
		{depscan.OSVComponent, m, false},
		{depscan.ScalibrComponent, nil, false},
	} {
		if got := depsOnlineAttached(c.component, c.m); got != c.want {
			t.Errorf("depsOnlineAttached(%s, matcher %v) = %v", c.component, c.m != nil, got)
		}
	}
}

// TestManagedNodeNeverAwaitsTheAccept is audit finding 3: a managed node
// cannot give the accept (its databases come from the organization's
// mirror), so its scans run and keep reporting whatever the driver finds
// (database_missing with no mirror), never database_not_accepted.
func TestManagedNodeNeverAwaitsTheAccept(t *testing.T) {
	useRemote(t)
	cfgPath, _ := scanConsentConfig(t)
	ctx := context.Background()
	e, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	if !e.awaitingAccept() {
		t.Fatal("setup: an individual node with no database must await the accept")
	}
	e.managed = true
	if e.awaitingAccept() {
		t.Fatal("a managed node awaits an accept it cannot give")
	}
	d := &countingDriver{}
	res, err := e.scanOne(ctx, d, t.TempDir(), secscan.Target{Scope: policy.FindingScopeManual}, false, nil, false)
	if err != nil || d.scans != 1 || res.Coverage.Reason == depscan.ReasonDBNotAccepted {
		t.Fatalf("managed scan: %+v %v (scans %d)", res.Coverage, err, d.scans)
	}
}
