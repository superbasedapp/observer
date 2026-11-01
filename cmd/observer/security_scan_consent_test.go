//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_scan_consent_test.go is the operator's ruling PT-19 (2), lane
// sec-deps4 item 2: the scanners' OSV databases download only after the
// developer's one-time accept, on both driver paths and on `observer
// security scan db refresh`; before it nothing claims clean.

// countingRemote counts the database requests and fails each one, so a
// test proves whether the download ran without any network.
type countingRemote struct{ calls atomic.Int64 }

func (r *countingRemote) Head(context.Context, string) (osvdb.Meta, error) {
	r.calls.Add(1)
	return osvdb.Meta{}, errors.New("test: no network")
}

func (r *countingRemote) Get(context.Context, string) (osvdb.Meta, io.ReadCloser, error) {
	r.calls.Add(1)
	return osvdb.Meta{}, nil, errors.New("test: no network")
}

// useRemote swaps the download's network side for the test.
func useRemote(t *testing.T) *countingRemote {
	t.Helper()
	r := &countingRemote{}
	old := depsOSVRemote
	depsOSVRemote = func() osvdb.Remote { return r }
	t.Cleanup(func() { depsOSVRemote = old })
	return r
}

// scanConsentConfig writes a config that selects both drivers, online
// checks off (the database accept stands on its own).
func scanConsentConfig(t *testing.T) (cfgPath, secDir string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + strconv.Quote(filepath.Join(dir, "observer.db")) +
		"\n[components]\nadd = [\"security.deps\", \"security.scan.scalibr\", \"security.scan.osv\"]\n[security.deps]\nonline = false\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, secposture.LayoutFor(cfgPath).Dir
}

// TestScannerDBWaitsForTheAccept: before the accept neither driver's loop
// downloads anything or scans, and a pass stays due so the accept is
// picked up at the next tick; after the accept both loops download (here,
// try to) with online checks off.
func TestScannerDBWaitsForTheAccept(t *testing.T) {
	remote := useRemote(t)
	cfgPath, secDir := scanConsentConfig(t)
	ctx := context.Background()
	for _, component := range []string{depscan.ScalibrComponent, depscan.OSVComponent} {
		var lastDB time.Time
		if err := depsScanPass(ctx, cfgPath, component, &lastDB); err != nil {
			t.Fatalf("%s pass: %v", component, err)
		}
		if remote.calls.Load() != 0 {
			t.Fatalf("%s downloaded before the accept", component)
		}
		if !lastDB.IsZero() {
			t.Fatalf("%s marked the download done although it waits for the accept", component)
		}
	}
	if _, err := osvdb.RecordConsent(secDir, "cli", "dev", time.Now(), testDepsSigningKey(t, secDir)); err != nil {
		t.Fatal(err)
	}
	for _, component := range []string{depscan.ScalibrComponent, depscan.OSVComponent} {
		before := remote.calls.Load()
		var lastDB time.Time
		if err := depsScanPass(ctx, cfgPath, component, &lastDB); err != nil {
			t.Fatalf("%s pass: %v", component, err)
		}
		if remote.calls.Load() == before {
			t.Fatalf("%s did not download after the accept", component)
		}
	}
}

// TestScanBeforeTheAcceptClaimsNothing: a scan with no database and no
// accept starts no driver, records no run and reads "not scanned" with
// the accept hint, never clean.
func TestScanBeforeTheAcceptClaimsNothing(t *testing.T) {
	useRemote(t)
	cfgPath, _ := scanConsentConfig(t)
	ctx := context.Background()
	e, err := openDepsScanEnv(ctx, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer e.cleanup()
	root := t.TempDir()
	d := &countingDriver{}
	res, err := e.scanOne(ctx, d, root, secscan.Target{Scope: policy.FindingScopeManual}, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.scans != 0 {
		t.Fatal("a driver ran before the accept")
	}
	if res.Coverage.Outcome != secscan.OutcomeNotScanned || res.Coverage.Reason != depscan.ReasonDBNotAccepted {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	if notes, err := e.st.SecLatestRunNotes(ctx, d.Row().ID); err != nil || len(notes) != 0 {
		t.Fatalf("a run was recorded: %v %v", notes, err)
	}
	var b bytes.Buffer
	writeScanReport(&b, depsScanReport{Driver: d.Row().ID, Result: res})
	if !strings.Contains(b.String(), "not scanned") || !strings.Contains(b.String(), "accept to download about 300 MB") || strings.Contains(b.String(), "no known vulnerabilities") {
		t.Fatalf("report:\n%s", b.String())
	}
}

// countingDriver is a driver that counts its scans and reports clean.
type countingDriver struct{ scans int }

func (d *countingDriver) Row() secscan.DriverRow { return depscan.OSVRow() }

func (d *countingDriver) Probe(context.Context) secscan.Probe { return secscan.Probe{} }

func (d *countingDriver) Scan(context.Context, secscan.Target) (secscan.Result, error) {
	d.scans++
	return secscan.Result{Coverage: secscan.Coverage{Outcome: secscan.OutcomeClean}}, nil
}

// TestScanDBAcceptVerb: `observer security scan db accept` shows the size
// and the source; without a terminal it records only with --yes, on a
// terminal only on a yes; it records the CLI and the account; a managed
// node records nothing. The status and db refresh say what is owed.
func TestScanDBAcceptVerb(t *testing.T) {
	remote := useRemote(t)
	cfgPath, secDir := scanConsentConfig(t)
	ctx := context.Background()
	open := func() *depsScanEnv {
		e, err := openDepsScanEnv(ctx, cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.cleanup)
		return e
	}
	e := open()
	var status bytes.Buffer
	writeDBDownloadState(&status, e)
	if !strings.Contains(status.String(), "databases not downloaded: accept to download about 300 MB from osv-vulnerabilities.storage.googleapis.com") {
		t.Fatalf("status before the accept:\n%s", status.String())
	}
	var refresh bytes.Buffer
	if err := writeDBRefresh(ctx, &refresh, e); err != nil || !strings.Contains(refresh.String(), "accept to download") || remote.calls.Load() != 0 {
		t.Fatalf("db refresh before the accept: %q %v (calls %d)", refresh.String(), err, remote.calls.Load())
	}

	var out bytes.Buffer
	if err := runDBAccept(&out, strings.NewReader(""), e, false, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() || !strings.Contains(out.String(), "Nothing recorded") || !strings.Contains(out.String(), "300 MB") {
		t.Fatalf("no terminal, no --yes:\n%s", out.String())
	}
	out.Reset()
	if err := runDBAccept(&out, strings.NewReader("no\n"), e, false, true, time.Now()); err != nil || osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatalf("a no on the terminal recorded: %v\n%s", err, out.String())
	}
	managed := open()
	managed.managed = true
	out.Reset()
	if err := runDBAccept(&out, strings.NewReader("y\n"), managed, true, true, time.Now()); err != nil || osvdb.ReadConsent(secDir, depsRecordKey(secDir)).Accepted() {
		t.Fatalf("a managed node recorded the accept: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := runDBAccept(&out, strings.NewReader("y\n"), e, false, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := osvdb.ReadConsent(secDir, depsRecordKey(secDir))
	if !c.Accepted() || c.Surface != "cli" {
		t.Fatalf("a yes did not record the CLI accept: %+v\n%s", c, out.String())
	}
	if c.By != depsLocalAccount() {
		t.Errorf("by %q, want the local account %q", c.By, depsLocalAccount())
	}
	status.Reset()
	writeDBDownloadState(&status, open())
	if !strings.HasPrefix(status.String(), "database download: on") || !strings.Contains(status.String(), "(cli") {
		t.Fatalf("status after the accept:\n%s", status.String())
	}
	out.Reset()
	if err := runDBAccept(&out, strings.NewReader(""), open(), true, false, time.Now()); err != nil || !strings.Contains(out.String(), "Already accepted") {
		t.Fatalf("a second accept: %v\n%s", err, out.String())
	}
}

// TestScannerDBDashSeam: the dashboard seam reads the same gate and
// records the accept as "dashboard"; with no driver selected it refuses.
func TestScannerDBDashSeam(t *testing.T) {
	useRemote(t)
	cfgPath, secDir := scanConsentConfig(t)
	ctx := context.Background()
	seam := scannerDBDash(cfgPath, nil)
	st, err := seam.Status(ctx)
	if err != nil || st.Accepted || st.Blocked != depscan.ReasonDBNotAccepted || st.ApproxMB != osvdb.ApproxDownloadMB || st.Source != osvdb.Source || st.Text == "" {
		t.Fatalf("status before %+v %v", st, err)
	}
	if err := seam.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	if c := osvdb.ReadConsent(secDir, depsRecordKey(secDir)); !c.Accepted() || c.Surface != "dashboard" {
		t.Fatalf("record %+v", c)
	}
	if st, _ := seam.Status(ctx); !st.Accepted || st.Blocked != "" || st.AcceptedOn != "dashboard" {
		t.Fatalf("status after %+v", st)
	}
	none := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(none, []byte("[components]\nremove = [\"security.scan.scalibr\", \"security.scan.osv\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scannerDBDash(none, nil).Accept(ctx); err == nil {
		t.Fatal("an install with no driver selected recorded the accept")
	}
}
