//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_image_trivy

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivydb"
)

// security_scan_trivy_daemon_test.go pins the daemon's refresh of Trivy's
// database (maybeRefreshTrivyDB, called from depsScanPass): a closed gate
// (the components not selected, no accept, a managed node) asks the
// registry nothing; after the accept a due database downloads; within the
// 6 h floor or before the database's NextUpdate nothing is asked; a failed
// refresh keeps the last good database; a scan that holds the lease is not
// raced.

// trivyLayerNext is trivyLayer with the database's NextUpdate set.
func trivyLayerNext(t *testing.T, next time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	meta := `{"Version":2,"NextUpdate":"` + next.UTC().Format(time.RFC3339) + `","UpdatedAt":"2026-11-04T01:28:23Z"}`
	for _, f := range []struct{ name, body string }{{trivydb.DBFile, "BOLT"}, {trivydb.MetadataFile, meta}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestTrivyDBDaemonRefreshGate(t *testing.T) {
	cases := []struct {
		name       string
		components string
		accept     bool
		managed    bool
	}{
		{name: "the image driver's components not selected", components: `"security.deps"`, accept: false},
		{name: "the Trivy binary's row not selected", components: `"security.deps", "security.scan.image.trivy"`, accept: true},
		{name: "not accepted", components: allTrivyComponents},
		{name: "a managed node, even accepted", components: allTrivyComponents, accept: true, managed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := trivyTestEnv(t, tc.components)
			if tc.accept {
				acceptTrivy(t, e)
			}
			e.managed = tc.managed
			f := &fakeTrivyDB{layer: trivyLayer(t)}
			swapTrivyDB(t, f)
			if maybeRefreshTrivyDB(context.Background(), e, time.Now()) || f.calls != 0 {
				t.Fatalf("a closed gate asked the registry (%d requests)", f.calls)
			}
			s, err := trivyDBStore()
			if err != nil {
				t.Fatal(err)
			}
			if s.State().Installed() {
				t.Fatal("a closed gate installed a database")
			}
		})
	}
}

func TestTrivyDBDaemonRefreshCadence(t *testing.T) {
	e, _ := trivyTestEnv(t, allTrivyComponents)
	acceptTrivy(t, e)
	ctx := context.Background()
	now := time.Now()
	f := &fakeTrivyDB{layer: trivyLayerNext(t, now.Add(8*time.Hour))}
	swapTrivyDB(t, f)

	if !maybeRefreshTrivyDB(ctx, e, now) || f.calls != 1 {
		t.Fatalf("a due database after the accept: %d requests", f.calls)
	}
	s, _ := trivyDBStore()
	if !s.State().Installed() {
		t.Fatal("the database was not installed")
	}
	// Within the 6 h floor: nothing asked.
	if maybeRefreshTrivyDB(ctx, e, now.Add(time.Hour)) || f.calls != 1 {
		t.Fatalf("within 6 h: %d requests", f.calls)
	}
	// Past 6 h but before the database's own NextUpdate: nothing asked.
	if maybeRefreshTrivyDB(ctx, e, now.Add(7*time.Hour)) || f.calls != 1 {
		t.Fatalf("before NextUpdate: %d requests", f.calls)
	}
	// Due again, the registry down: fail-soft, the installed database stays.
	f.fail = true
	if !maybeRefreshTrivyDB(ctx, e, now.Add(9*time.Hour)) || f.calls != 2 {
		t.Fatalf("due again: %d requests", f.calls)
	}
	st := s.State()
	if !st.Installed() || st.LastError == "" {
		t.Fatalf("a failed refresh must keep the database and record the failure: %+v", st)
	}
	// A scan holding the lease is not raced: nothing asked, tried next tick.
	release, ok, err := dblease.TryAcquire(e.dir, depsScanLeaseName)
	if err != nil || !ok {
		t.Fatalf("lease: %v %v", ok, err)
	}
	f.fail = false
	if maybeRefreshTrivyDB(ctx, e, now.Add(16*time.Hour)) || f.calls != 2 {
		t.Fatalf("under another scan's lease: %d requests", f.calls)
	}
	release()
	if !maybeRefreshTrivyDB(ctx, e, now.Add(16*time.Hour)) || f.calls != 3 {
		t.Fatalf("after the lease: %d requests", f.calls)
	}
}
