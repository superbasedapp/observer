package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_apply_test.go is the W3 acceptance suite for §3.7 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md.
//
// Nothing here touches ~/.observer, the real daemon, or a real release
// artifact. The "binaries" are shell scripts and the archives are built in a
// temp dir, which is what lets acceptance 7 — "three separate forced failures
// each end with the node running the OLD binary and reporting rolled_back,
// with NO SUPERVISOR INSTALLED" — be a unit test rather than a manual drill.

// ---------------------------------------------------------------- fake store

// fakeUpdateStore is an in-memory updateStateStore. It enforces the SAME
// transition rules the real store does (update.Transition), because a test
// store that accepted any state would make "state transitions legal" vacuous.
type fakeUpdateStore struct {
	row           store.UpdateStateRow
	events        []store.UpdateEventRow
	schema        int
	schemaAt      int // schema reported AFTER the swap, to simulate a migration
	swapped       bool
	snapshot      string
	snapErr       error
	snapshotCalls int
}

func newFakeUpdateStore() *fakeUpdateStore {
	return &fakeUpdateStore{row: store.UpdateStateRow{NodeState: update.DefaultNodeState()}, schema: 104, schemaAt: 104}
}

func (f *fakeUpdateStore) LoadUpdateState(context.Context) (store.UpdateStateRow, error) {
	return f.row, nil
}

func (f *fakeUpdateStore) SaveUpdateState(_ context.Context, row store.UpdateStateRow) error {
	if !update.KnownState(row.State) {
		return fmt.Errorf("fake store: unknown state %q", row.State)
	}
	f.row = row
	return nil
}

func (f *fakeUpdateStore) AppendUpdateEvent(_ context.Context, ev store.UpdateEventRow) error {
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeUpdateStore) TransitionUpdateState(ctx context.Context, next update.State, mutate func(*store.UpdateStateRow), ev store.UpdateEventRow) error {
	moved, err := update.Transition(f.row.State, next)
	if err != nil {
		return err
	}
	row := f.row
	row.State = moved
	if mutate != nil {
		mutate(&row)
	}
	if err := f.SaveUpdateState(ctx, row); err != nil {
		return err
	}
	if ev.State == "" {
		ev.State = moved
	}
	return f.AppendUpdateEvent(ctx, ev)
}

func (f *fakeUpdateStore) SchemaVersion(context.Context) (int, error) {
	if f.swapped {
		return f.schemaAt, nil
	}
	return f.schema, nil
}

func (f *fakeUpdateStore) SnapshotDatabase(_ context.Context, dest string) error {
	f.snapshotCalls++
	if f.snapErr != nil {
		return f.snapErr
	}
	f.snapshot = dest
	return os.WriteFile(dest, []byte("SNAPSHOT"), 0o600)
}

func (f *fakeUpdateStore) states() []update.State {
	out := make([]update.State, 0, len(f.events))
	for _, e := range f.events {
		out = append(out, e.State)
	}
	return out
}

// --------------------------------------------------------------- fixture rig

// applyFixture is one fully-wired apply, ready to run.
type applyFixture struct {
	t        *testing.T
	dir      string
	exePath  string
	stateDir string
	dbPath   string
	archive  []byte
	deps     applyDeps
	opts     applyOptions
	st       *fakeUpdateStore
	gate     *quiesce.Gate
	signKey  ed25519.PrivateKey
}

const fixtureTargetVersion = "v9.9.9"

// newApplyFixture builds a real tar.gz artifact, a fake "installed binary",
// and a signing key, then wires an apply around them.
func newApplyFixture(t *testing.T) *applyFixture {
	t.Helper()
	dir := t.TempDir()
	exePath := filepath.Join(dir, "bin", "observer")
	if err := os.MkdirAll(filepath.Dir(exePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\necho OLD\n"), 0o755); err != nil { //nolint:gosec // a fake binary in a temp dir
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "observer.db")
	if err := os.WriteFile(dbPath, []byte("LIVE-DB"), 0o600); err != nil {
		t.Fatal(err)
	}

	member := []byte("#!/bin/sh\necho NEW " + fixtureTargetVersion + "\n")
	archive := buildTarGz(t, map[string]tarEntrySpec{
		"observer":   {body: member},
		"superbased": {link: "observer"},
	})

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	art := update.Artifact{
		Kind: "agent", OS: runtime.GOOS, Arch: runtime.GOARCH,
		ArchiveType: update.ArchiveTarGz,
		Filename:    "observer-" + fixtureTargetVersion + "-test.tar.gz",
		SizeBytes:   int64(len(archive)),
		SHA256:      hexSum(archive),
		Member:      "observer", MemberSHA256: hexSum(member),
		AliasMembers:    []string{"superbased"},
		UpstreamSigType: update.SigTypeEd25519,
		UpstreamSig:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, archive)),
	}
	man := update.Manifest{
		Schema: update.SchemaV1, Channel: update.ChannelStable,
		ManifestVersion: 17, Version: fixtureTargetVersion,
		Artifacts: []update.Artifact{art},
	}

	st := newFakeUpdateStore()
	gate := quiesce.NewGate()
	f := &applyFixture{
		t: t, dir: dir, exePath: exePath, stateDir: filepath.Join(dir, "updates"),
		dbPath: dbPath, archive: archive, st: st, gate: gate, signKey: priv,
	}
	f.deps = applyDeps{
		Store:      st,
		Quiescence: &quiesce.Quiescence{Gate: gate},
		Download: func(_ context.Context, _, _ string, dst io.Writer, maxBytes int64) error {
			if maxBytes > 0 && int64(len(archive)) > maxBytes {
				return errors.New("artifact exceeds the ceiling")
			}
			_, err := dst.Write(archive)
			return err
		},
		VerifyVendorSignature: func(string, update.Artifact) error { return nil },
		Probe: func(context.Context, string) (string, error) {
			return "observer " + fixtureTargetVersion, nil
		},
		Supervise: func(context.Context, string, string, time.Duration) (handshakeResult, error) {
			st.swapped = true
			return handshakeResult{Ready: true, Detail: "self-check passed", ChildPID: 4242}, nil
		},
		FS:   osSwapFS{},
		GOOS: runtime.GOOS,
	}
	f.opts = applyOptions{
		Manifest: man, Artifact: art,
		Installed: update.Installed{
			Version: "v9.9.8", SchemaVersion: 104, ExecPath: exePath,
			Detection: update.Detection{Method: update.MethodBinary, SelfApply: true},
		},
		StateDir: f.stateDir, DBPath: dbPath,
		DrainTimeout: 2 * time.Second, HandshakeTimeout: time.Second,
		TargetSchemaVersion: 104, // same schema => no snapshot, unless a test says otherwise
	}
	return f
}

func (f *applyFixture) run() (applyOutcome, error) {
	f.t.Helper()
	return runUpdateApply(context.Background(), f.deps, f.opts)
}

// installedBinary reads what is at exePath now — the single most important
// assertion in the file, because "the running binary is unchanged afterwards"
// is what fail-closed means.
func (f *applyFixture) installedBinary() string {
	f.t.Helper()
	b, err := os.ReadFile(f.exePath)
	if err != nil {
		f.t.Fatalf("no executable at %s: %v", f.exePath, err)
	}
	return string(b)
}

type tarEntrySpec struct {
	body []byte
	link string
}

func buildTarGz(t *testing.T, entries map[string]tarEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// Deterministic order: the member first, then the alias.
	names := []string{"observer", "superbased"}
	for _, name := range names {
		spec, ok := entries[name]
		if !ok {
			continue
		}
		if spec.link != "" {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: spec.link, Mode: 0o777}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(spec.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(spec.body); err != nil {
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

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ------------------------------------------------------------- happy path

// TestApplySucceedsAndTellsTheCallerToExit is the reference run: every gate
// passes, the binary is replaced, and the outcome says the child is the
// daemon now.
func TestApplySucceedsAndTellsTheCallerToExit(t *testing.T) {
	f := newApplyFixture(t)
	out, err := f.run()
	if err != nil {
		t.Fatalf("apply: %v (%s)", err, out.Detail)
	}
	if !out.Applied || out.State != update.StateApplied {
		t.Fatalf("outcome = %+v, want applied", out)
	}
	if got := f.installedBinary(); !strings.Contains(got, "NEW") {
		t.Fatalf("the executable was not replaced: %q", got)
	}
	// The alias member must NOT have been extracted as a second executable.
	if _, err := os.Stat(filepath.Join(f.stateDir, fixtureTargetVersion, "superbased")); err == nil {
		t.Error("the declared alias member was extracted; it must be skipped")
	}
	if f.st.snapshotCalls != 0 {
		t.Errorf("a snapshot was taken (%d calls) although the target does not advance the schema", f.st.snapshotCalls)
	}
	if f.gate.Draining() {
		t.Error("admission was left closed after a successful apply")
	}
	wantSeen := map[update.State]bool{update.StateDownloading: true, update.StateVerified: true, update.StateApplying: true, update.StateApplied: true}
	for _, s := range f.st.states() {
		delete(wantSeen, s)
	}
	if len(wantSeen) != 0 {
		t.Errorf("ledger states = %v, missing %v", f.st.states(), wantSeen)
	}
}

// ------------------------------------------------------------ fail-closed

// TestApplyIsFailClosed walks the refusal table. Every row must leave the OLD
// binary in place — that assertion is repeated per row on purpose, because it
// is the property, not a side effect.
func TestApplyIsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(f *applyFixture)
		wantState  update.State
		wantClass  update.ErrorClass
		wantReason update.Reason
		wantDefer  bool
	}{
		{
			name: "hash mismatch aborts and discards the download",
			mutate: func(f *applyFixture) {
				f.opts.Artifact.SHA256 = strings.Repeat("a", 64)
				f.opts.Manifest.Artifacts[0].SHA256 = f.opts.Artifact.SHA256
			},
			wantState: update.StateFailed, wantClass: update.ErrorHash,
		},
		{
			name: "member hash mismatch aborts",
			mutate: func(f *applyFixture) {
				f.opts.Artifact.MemberSHA256 = strings.Repeat("b", 64)
				f.opts.Manifest.Artifacts[0].MemberSHA256 = f.opts.Artifact.MemberSHA256
			},
			wantState: update.StateFailed, wantClass: update.ErrorHash,
		},
		{
			name: "a probe returning the wrong version aborts",
			mutate: func(f *applyFixture) {
				f.deps.Probe = func(context.Context, string) (string, error) { return "observer v1.0.0", nil }
			},
			wantState: update.StateFailed, wantClass: update.ErrorProbe,
		},
		{
			name: "a bad vendor signature aborts",
			mutate: func(f *applyFixture) {
				f.deps.VerifyVendorSignature = func(string, update.Artifact) error {
					return errors.New("signature does not verify")
				}
			},
			wantState: update.StateFailed, wantClass: update.ErrorSignature,
		},
		{
			name: "a build with no vendor key blocks rather than failing",
			mutate: func(f *applyFixture) {
				f.deps.VerifyVendorSignature = func(string, update.Artifact) error { return errNoVendorKeyLocal }
			},
			wantState: update.StateBlocked, wantReason: update.ReasonUnsignedArtifact, wantDefer: true,
		},
		{
			name: "an unwritable target reports binary_readonly",
			mutate: func(f *applyFixture) {
				f.opts.Installed.Detection = update.Detection{Method: update.MethodBinaryReadOnly, SelfApply: false}
			},
			wantState: update.StateBlocked, wantReason: update.ReasonNotWritable, wantDefer: true,
		},
		{
			name: "an npm-owned binary blocks with the install method",
			mutate: func(f *applyFixture) {
				f.opts.Installed.Detection = update.Detection{Method: update.MethodNPM, SelfApply: false}
			},
			wantState: update.StateBlocked, wantReason: update.ReasonInstallMethod, wantDefer: true,
		},
		{
			name: "outside the maintenance window the apply defers",
			mutate: func(f *applyFixture) {
				// A one-minute window on the far side of the clock.
				w, err := update.ParseWindow(farWindow(time.Now()))
				if err != nil {
					f.t.Fatal(err)
				}
				f.opts.Window = w
			},
			wantState: update.StateAvailable, wantReason: update.ReasonWindow, wantDefer: true,
		},
		{
			name: "a snapshot that cannot be written aborts before the swap",
			mutate: func(f *applyFixture) {
				f.opts.TargetSchemaVersion = 105 // advances the schema
				f.st.snapErr = errors.New("no space left on device")
			},
			wantState: update.StateFailed, wantClass: update.ErrorPermission,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			tc.mutate(f)
			out, _ := f.run()
			if out.State != tc.wantState {
				t.Errorf("state = %q, want %q (detail: %s)", out.State, tc.wantState, out.Detail)
			}
			if tc.wantClass != "" && out.ErrorClass != tc.wantClass {
				t.Errorf("error_class = %q, want %q", out.ErrorClass, tc.wantClass)
			}
			if tc.wantReason != "" && out.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", out.Reason, tc.wantReason)
			}
			if out.Deferred != tc.wantDefer {
				t.Errorf("deferred = %v, want %v", out.Deferred, tc.wantDefer)
			}
			if out.Applied {
				t.Error("a refused apply reported Applied")
			}
			if got := f.installedBinary(); !strings.Contains(got, "OLD") {
				t.Errorf("the running binary was replaced by a REFUSED apply: %q", got)
			}
			if f.gate.Draining() {
				t.Error("admission was left closed after a refused apply (R13)")
			}
		})
	}
}

// farWindow returns an HH:MM-HH:MM window that does not contain now.
func farWindow(now time.Time) string {
	start := now.Add(3 * time.Hour)
	end := start.Add(time.Hour)
	return fmt.Sprintf("%02d:%02d-%02d:%02d", start.Hour(), start.Minute(), end.Hour(), end.Minute())
}

// TestUnsignedArtifactBlocksWithoutDownloadingAByte pins the plan's exact
// wording: an artifact with no upstream_sig is refused "without downloading a
// second byte".
func TestUnsignedArtifactBlocksWithoutDownloadingAByte(t *testing.T) {
	f := newApplyFixture(t)
	f.opts.Artifact.UpstreamSig = ""
	f.opts.Manifest.Artifacts[0].UpstreamSig = ""
	downloads := 0
	f.deps.Download = func(context.Context, string, string, io.Writer, int64) error {
		downloads++
		return nil
	}
	out, err := f.run()
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if out.State != update.StateBlocked || out.Reason != update.ReasonUnsignedArtifact {
		t.Fatalf("outcome = %+v, want blocked{unsigned_artifact}", out)
	}
	if downloads != 0 {
		t.Fatalf("the artifact was downloaded %d time(s) despite having no vendor signature", downloads)
	}
}

// ------------------------------------------------------------------ drain

// TestDrainTimeoutAbortsTheApplyAndRestoresAdmission is ruling R13 at the
// apply level.
func TestDrainTimeoutAbortsTheApplyAndRestoresAdmission(t *testing.T) {
	f := newApplyFixture(t)
	f.gate.Enter() // an in-flight request that never finishes
	f.opts.DrainTimeout = 60 * time.Millisecond

	out, _ := f.run()
	if out.State != update.StateFailed || out.ErrorClass != update.ErrorDrain {
		t.Fatalf("outcome = %+v, want failed{drain}", out)
	}
	if !strings.Contains(out.Detail, "admission has been restored") {
		t.Errorf("detail does not state that admission was restored: %q", out.Detail)
	}
	if f.gate.Draining() {
		t.Fatal("the proxy is still refusing traffic after an abandoned apply — R13 violated")
	}
	if !f.gate.Enter() {
		t.Fatal("admission was not restored")
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatal("the binary was swapped despite an incomplete drain")
	}
}

// TestLivePTYDefersUnlessForcedInWindow is §3.7 step 4a's PTY rule at the
// apply level, and it asserts the thing that makes a DEFER different from a
// failure: the proxy never refused anyone.
func TestLivePTYDefersUnlessForcedInWindow(t *testing.T) {
	for _, tc := range []struct {
		name              string
		force, inWindow   bool
		wantDeferred      bool
		wantBinaryChanged bool
	}{
		{"a live PTY defers", false, false, true, false},
		{"--force alone still defers", true, false, true, false},
		{"an admin window alone still defers", false, true, true, false},
		{"--force inside an admin window proceeds", true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			f.deps.Quiescence = &quiesce.Quiescence{
				Gate: f.gate,
				Live: []quiesce.LiveWork{{
					Name: "dashboard terminal sessions", Count: func() int { return 1 }, Forcible: true,
				}},
			}
			f.opts.Force, f.opts.InAdminWindow = tc.force, tc.inWindow
			out, _ := f.run()
			if out.Deferred != tc.wantDeferred {
				t.Fatalf("deferred = %v, want %v (state %q, detail %q)", out.Deferred, tc.wantDeferred, out.State, out.Detail)
			}
			changed := strings.Contains(f.installedBinary(), "NEW")
			if changed != tc.wantBinaryChanged {
				t.Errorf("binary replaced = %v, want %v", changed, tc.wantBinaryChanged)
			}
			if tc.wantDeferred && f.gate.InFlight() != 0 {
				t.Error("a deferred apply left in-flight bookkeeping behind")
			}
		})
	}
}

// --------------------------------------------------------------- rollback

// TestThreeHandshakeFailureShapesAllRollBack is acceptance 7. All three end
// with the OLD binary running and state=rolled_back, and the actor is the
// still-live parent — no supervisor exists in this test environment.
func TestThreeHandshakeFailureShapesAllRollBack(t *testing.T) {
	for _, tc := range []struct {
		name      string
		supervise func(*fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error)
	}{
		{
			name: "(a) the child fails its self-check",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "the new binary reported a failed self-check: version mismatch"},
						errors.New("self-check failed")
				}
			},
		},
		{
			name: "(b) the child exits non-zero before its self-check",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "the new binary exited before completing its self-check (exit status 1)"},
						errors.New("child exited")
				}
			},
		},
		{
			name: "(c) the child hangs and never reports",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "the new binary did not report within the 1s handshake timeout"},
						errors.New("handshake timeout")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			f.deps.Supervise = tc.supervise(f.st)
			out, _ := f.run()
			if out.State != update.StateRolledBack || !out.RolledBack {
				t.Fatalf("outcome = %+v, want rolled_back", out)
			}
			if out.ErrorClass != update.ErrorHealthcheck {
				t.Errorf("error_class = %q, want healthcheck", out.ErrorClass)
			}
			if got := f.installedBinary(); !strings.Contains(got, "OLD") {
				t.Fatalf("the OLD binary was not restored; %s holds %q", f.exePath, got)
			}
			if f.gate.Draining() {
				t.Error("admission was left closed after a rollback")
			}
			// The ledger must record it, because the org board learns the
			// state from the posture and the OPERATOR learns why from here.
			last := f.st.events[len(f.st.events)-1]
			if last.State != update.StateRolledBack || last.Detail == "" {
				t.Errorf("last ledger event = %+v, want a rolled_back row with a reason", last)
			}
		})
	}
}

// TestRollbackAcrossASchemaAdvanceRestoresBothAndNamesTheWindow is
// acceptance 8: binary AND snapshot, with the discarded window stated.
func TestRollbackAcrossASchemaAdvanceRestoresBothAndNamesTheWindow(t *testing.T) {
	f := newApplyFixture(t)
	f.opts.TargetSchemaVersion = 105 // the target advances the schema
	f.st.schema, f.st.schemaAt = 104, 105
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		// Simulate the child having migrated the database before failing.
		if err := os.WriteFile(f.dbPath, []byte("MIGRATED-DB"), 0o600); err != nil {
			t.Fatal(err)
		}
		return handshakeResult{Detail: "self-check failed after migrating"}, errors.New("self-check failed")
	}
	out, _ := f.run()
	if out.State != update.StateRolledBack {
		t.Fatalf("outcome = %+v, want rolled_back", out)
	}
	if f.st.snapshotCalls != 1 {
		t.Fatalf("snapshot calls = %d, want exactly 1 (the target advances the schema)", f.st.snapshotCalls)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatalf("the OLD binary was not restored: %q", got)
	}
	db, err := os.ReadFile(f.dbPath)
	if err != nil {
		t.Fatalf("no database at %s: %v", f.dbPath, err)
	}
	if string(db) != "SNAPSHOT" {
		t.Fatalf("database holds %q, want the pre-apply SNAPSHOT restored", db)
	}
	if out.DiscardedWindowFrom.IsZero() {
		t.Error("the discarded data window was not recorded (ruling R15)")
	}
	if !strings.Contains(out.Detail, "discarded") {
		t.Errorf("detail does not name the discarded window: %q", out.Detail)
	}
}

// TestRollbackIsRefusedWhenTheSchemaAdvancedWithNoSnapshot pins the
// "should be unreachable" branch. Restoring an older binary against a newer
// forward-only schema is a corruption risk, so the node stops for an operator
// instead of guessing.
func TestRollbackIsRefusedWhenTheSchemaAdvancedWithNoSnapshot(t *testing.T) {
	f := newApplyFixture(t)
	f.opts.TargetSchemaVersion = 104 // planner sees no advance -> no snapshot
	f.st.schema, f.st.schemaAt = 104, 105
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		return handshakeResult{Detail: "self-check failed"}, errors.New("self-check failed")
	}
	out, _ := f.run()
	if out.State != update.StateFailed {
		t.Fatalf("outcome = %+v, want failed (a refused rollback)", out)
	}
	if out.RolledBack {
		t.Error("the outcome claims a rollback that was refused")
	}
	if !strings.Contains(out.Detail, "corruption risk") {
		t.Errorf("detail does not explain the refusal: %q", out.Detail)
	}
}

// --------------------------------------------------------------- dry run

// TestDryRunPerformsNothingAndNamesTheSnapshot: `--dry-run` must print
// whether a migration — and therefore a DB snapshot — is involved.
func TestDryRunPerformsNothingAndNamesTheSnapshot(t *testing.T) {
	f := newApplyFixture(t)
	f.opts.DryRun = true
	f.opts.TargetSchemaVersion = 0 // unknown => treated as migrating
	downloads := 0
	f.deps.Download = func(context.Context, string, string, io.Writer, int64) error {
		downloads++
		return nil
	}
	out, err := f.run()
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if downloads != 0 {
		t.Fatalf("a dry run downloaded %d artifact(s)", downloads)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatal("a dry run replaced the binary")
	}
	joined := strings.Join(out.Steps, "\n")
	if !strings.Contains(joined, "snapshot the database") {
		t.Errorf("dry-run steps do not name the snapshot:\n%s", joined)
	}
}

// ---------------------------------------------------------- probe matching

func TestVersionProbeMatches(t *testing.T) {
	for _, tc := range []struct {
		got, target string
		want        bool
	}{
		{"v1.33.0", "v1.33.0", true},
		{"observer version v1.33.0", "v1.33.0", true},
		{"observer version 1.33.0", "v1.33.0", true},
		{"observer version v1.32.0", "v1.33.0", false},
		{"", "v1.33.0", false},
		{"v1.33.0", "", false},
		{"observer version v1.33.0-rc.1", "v1.33.0", false},
		// L10: an output that names the target AND another version is
		// exactly what a loose contains-check waved through, and exactly the
		// case where the staged binary is not what the manifest says.
		{"observer v1.32.0 (v1.33.0 available)", "v1.33.0", false},
		{"observer v1.33.0 (build 2026-09-08, go1.24.2)", "v1.33.0", true},
		{"observer prerelease build", "v1.33.0", false},
	} {
		if got := versionProbeMatches(tc.got, tc.target); got != tc.want {
			t.Errorf("versionProbeMatches(%q, %q) = %v, want %v", tc.got, tc.target, got, tc.want)
		}
	}
}

// ------------------------------------------------------------- downgrade

// TestDowngradeIsRefusedUnlessExplicitlyMinted is the TUF rollback defence at
// the APPLY boundary (§3.2 rule 7). update.Verify already applies it when the
// rail accepts a manifest, but an apply can also run from a manifest cached
// in update_state, and a rule that guards only one of two entry points is not
// a rule.
func TestDowngradeIsRefusedUnlessExplicitlyMinted(t *testing.T) {
	for _, tc := range []struct {
		name             string
		installed        string
		allowDowngradeTo string
		nodeConsent      bool
		wantBlocked      bool
	}{
		{"a lower target is refused outright", "v9.9.9", "", false, true},
		{"an equal target is refused outright", fixtureTargetVersion, "", false, true},
		{"admin consent alone is not enough", "v9.9.9", fixtureTargetVersion, false, true},
		{"node consent alone is not enough", "v9.9.9", "", true, true},
		{"a different allow_downgrade_to does not license this one", "v9.9.9", "v1.0.0", true, true},
		{"both, naming this exact target, proceeds", "v9.9.9", fixtureTargetVersion, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			f.opts.Installed.Version = tc.installed
			f.opts.Manifest.AllowDowngradeTo = tc.allowDowngradeTo
			f.opts.AllowDowngrade = tc.nodeConsent
			out, _ := f.run()
			if tc.wantBlocked {
				if out.State != update.StateBlocked || out.Reason != update.ReasonDowngrade {
					t.Fatalf("outcome = %+v, want blocked{downgrade_not_allowed}", out)
				}
				if !strings.Contains(f.installedBinary(), "OLD") {
					t.Fatal("a refused downgrade replaced the running binary")
				}
				return
			}
			if out.State == update.StateBlocked {
				t.Fatalf("an explicitly-minted, node-consented downgrade was refused: %+v", out)
			}
		})
	}
}

// ------------------------------------------------------------ auto-apply

// TestAutoApplyDefaultIsOffUnlessManaged is §3.9 as the surfaces resolve it:
// false for a BYO node, true under admin_managed, and an explicit node TOML
// value always winning in BOTH directions.
func TestAutoApplyDefaultIsOffUnlessManaged(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name         string
		explicit     *bool
		posture      update.ManagedPosture
		want         bool
		wantExplicit bool
	}{
		{"BYO node, nothing set", nil, update.ManagedPosture{}, false, false},
		{"admin_managed flips the default on", nil, update.ManagedPosture{AdminManaged: true}, true, false},
		{"enterprise grant flips the default on", nil, update.ManagedPosture{EnterpriseGranted: true}, true, false},
		{"an explicit false beats the managed default", &no, update.ManagedPosture{AdminManaged: true}, false, true},
		{"an explicit true beats the BYO default", &yes, update.ManagedPosture{}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.UpdateConfig{AutoApply: tc.explicit}
			got, explicit := cfg.EffectiveAutoApply(update.AutoApplyDefault(tc.posture))
			if got != tc.want {
				t.Errorf("effective auto_apply = %v, want %v", got, tc.want)
			}
			if explicit != tc.wantExplicit {
				t.Errorf("explicit = %v, want %v", explicit, tc.wantExplicit)
			}
			// And the surface must say WHO decided.
			why := update.AutoApplyReason(explicit, got, tc.posture)
			if why == "" {
				t.Fatal("no reason was produced")
			}
			if explicit && !strings.Contains(why, "[update].auto_apply") {
				t.Errorf("reason %q does not name the node's own config", why)
			}
		})
	}
}

// ------------------------------------------------- review fix round 2 (H1/M2)

// TestARollbackAfterTheListenersWereReleasedExitsNonZero is H1.
//
// The three failure shapes above prove the node ends up running the OLD
// binary. This proves the OLD PROCESS does not then linger as a zombie main
// PID with the proxy and dashboard sockets released and nobody listening —
// which is what happened before, because only out.Applied triggered an exit.
// Restart=always never fires on a process that does not exit, so the node was
// DOWN with no supervisor able to notice.
func TestARollbackAfterTheListenersWereReleasedExitsNonZero(t *testing.T) {
	for _, tc := range []struct {
		name      string
		supervise func(*fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error)
	}{
		{
			name: "(a) the child fails its self-check",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "failed self-check"}, errors.New("self-check failed")
				}
			},
		},
		{
			name: "(b) the child exits before its self-check",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "exited early"}, errors.New("child exited")
				}
			},
		},
		{
			name: "(c) the child hangs and never reports",
			supervise: func(st *fakeUpdateStore) func(context.Context, string, string, time.Duration) (handshakeResult, error) {
				return func(context.Context, string, string, time.Duration) (handshakeResult, error) {
					st.swapped = true
					return handshakeResult{Detail: "handshake timeout"}, errors.New("handshake timeout")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			// A runtime standing in for the daemon: it holds the listener
			// seam, and the fixture's Supervise releases it exactly where the
			// real one does — immediately before spawning the child.
			u := &updateRuntime{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			u.SetReleaseListeners(func() {})
			inner := tc.supervise(f.st)
			f.deps.Supervise = func(ctx context.Context, exe, stateDir string, d time.Duration) (handshakeResult, error) {
				u.releaseListenersNow()
				return inner(ctx, exe, stateDir, d)
			}

			out, _ := f.run()
			if !out.RolledBack {
				t.Fatalf("outcome = %+v, want a rollback", out)
			}
			if got := f.installedBinary(); !strings.Contains(got, "OLD") {
				t.Fatalf("the OLD binary was not restored: %q", got)
			}

			codes := make(chan int, 1)
			restore := updateExitFunc
			updateExitFunc = func(code int) { codes <- code }
			t.Cleanup(func() { updateExitFunc = restore })

			if !u.finishApply(out, fixtureTargetVersion) {
				t.Fatal("finishApply reported that this process survives; a parent with no listeners must not")
			}
			select {
			case code := <-codes:
				if code == 0 {
					t.Errorf("exit code = 0; a rollback is not a successful handover and a supervisor must be able to tell")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the exit seam never fired: the parent would linger with its sockets released and nobody listening")
			}
		})
	}
}

// TestAnApplyThatNeverReleasedItsListenersKeepsServing is the other half of
// the same rule: a blocked plan or a failed download changes nothing about
// this process, so it must NOT exit.
func TestAnApplyThatNeverReleasedItsListenersKeepsServing(t *testing.T) {
	u := &updateRuntime{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	u.SetReleaseListeners(func() { t.Fatal("the listeners must not be released by a plan that never got that far") })
	restore := updateExitFunc
	updateExitFunc = func(int) { t.Fatal("a daemon that never released its listeners must not exit") }
	t.Cleanup(func() { updateExitFunc = restore })
	if u.finishApply(applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorDownload}, "v9.9.9") {
		t.Fatal("finishApply ended a process that is still serving")
	}
}

// TestTheDatabaseIsClosedBeforeTheSnapshotIsRenamedOver is H1's second half.
//
// restoreDatabaseSnapshot renames the live file aside; a handle left open on
// the old inode keeps this process appending to observer.db.failed-update
// while hook processes, which open by path, write to the restored file. The
// discarded window would then be "until the operator notices" instead of the
// drain-plus-handshake ruling R15 states.
func TestTheDatabaseIsClosedBeforeTheSnapshotIsRenamedOver(t *testing.T) {
	f := newApplyFixture(t)
	f.opts.TargetSchemaVersion = 105
	f.st.schema, f.st.schemaAt = 104, 105

	var order []string
	dbWhenClosed := ""
	f.deps.CloseDB = func() error {
		b, _ := os.ReadFile(f.dbPath)
		dbWhenClosed = string(b)
		order = append(order, "close")
		return nil
	}
	reopened := newFakeUpdateStore()
	f.deps.ReopenStore = func() (updateStateStore, error) {
		order = append(order, "reopen")
		return reopened, nil
	}
	f.deps.Supervise = func(context.Context, string, string, time.Duration) (handshakeResult, error) {
		f.st.swapped = true
		if err := os.WriteFile(f.dbPath, []byte("MIGRATED-DB"), 0o600); err != nil {
			t.Fatal(err)
		}
		return handshakeResult{Detail: "self-check failed after migrating"}, errors.New("self-check failed")
	}

	out, _ := f.run()
	if out.State != update.StateRolledBack {
		t.Fatalf("outcome = %+v, want rolled_back", out)
	}
	if len(order) != 2 || order[0] != "close" || order[1] != "reopen" {
		t.Fatalf("call order = %v, want [close reopen]", order)
	}
	if dbWhenClosed != "MIGRATED-DB" {
		t.Fatalf("the handle was closed against %q, want the live MIGRATED-DB - it must close BEFORE the rename", dbWhenClosed)
	}
	if got, _ := os.ReadFile(f.dbPath); string(got) != "SNAPSHOT" {
		t.Fatalf("database holds %q, want the restored SNAPSHOT", got)
	}
	// The rollback's own ledger row must land in the file that SURVIVES the
	// restore, and it must name the discarded window.
	if len(reopened.events) == 0 {
		t.Fatal("no ledger row was written through the reopened handle; the rollback is invisible after the restore")
	}
	last := reopened.events[len(reopened.events)-1]
	if last.State != update.StateRolledBack || !strings.Contains(last.Detail, "discarded") {
		t.Errorf("ledger row = %+v, want a rolled_back row naming the discarded window", last)
	}
}

// TestTheManifestsSchemaVersionDecidesTheSnapshot is M2.
//
// Nothing set TargetSchemaVersion, so BuildApplyPlan's "zero means unknown
// means may advance" made NeedsDBSnapshot always true: a full VACUUM INTO of
// the whole database on EVERY apply, on a node whose database is measured in
// gigabytes. The manifest now carries the answer.
func TestTheManifestsSchemaVersionDecidesTheSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name          string
		schemaVersion int
		wantSnapshots int
	}{
		{name: "a manifest that declares the same schema takes no snapshot", schemaVersion: 104, wantSnapshots: 0},
		{name: "a manifest that declares a newer schema takes one", schemaVersion: 105, wantSnapshots: 1},
		{name: "a manifest that declares nothing stays conservative", schemaVersion: 0, wantSnapshots: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newApplyFixture(t)
			f.opts.Manifest.SchemaVersion = tc.schemaVersion
			// Exactly what both production wirings now do.
			f.opts.TargetSchemaVersion = f.opts.Manifest.SchemaVersion
			if _, err := f.run(); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if f.st.snapshotCalls != tc.wantSnapshots {
				t.Errorf("snapshot calls = %d, want %d", f.st.snapshotCalls, tc.wantSnapshots)
			}
		})
	}
}

// TestAnApplyIsBlockedWithoutDiskHeadroom is §2.4's headroom gate, which the
// plan promised and nothing implemented. It is a BLOCK, not a failure: an
// admin frees space or moves state_dir, and a node that keeps re-downloading
// an archive it cannot hold is the disk-exhaustion class the 2026-08-26 audit
// forbids.
func TestAnApplyIsBlockedWithoutDiskHeadroom(t *testing.T) {
	f := newApplyFixture(t)
	downloads := 0
	inner := f.deps.Download
	f.deps.Download = func(ctx context.Context, v, fn string, dst io.Writer, max int64) error {
		downloads++
		return inner(ctx, v, fn, dst, max)
	}
	f.deps.FreeBytes = func(string) (uint64, error) { return 1, nil } // one byte free

	out, err := f.run()
	if err != nil {
		t.Fatalf("a headroom block is a defer, not an error: %v", err)
	}
	if out.State != update.StateBlocked || out.Reason != update.ReasonNoDiskSpace || !out.Deferred {
		t.Fatalf("outcome = %+v, want blocked{no_disk_space} deferred", out)
	}
	if downloads != 0 {
		t.Errorf("the archive was downloaded (%d) before the headroom check", downloads)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatal("a blocked apply replaced the binary")
	}

	// With room, the same apply proceeds.
	f2 := newApplyFixture(t)
	f2.deps.FreeBytes = func(string) (uint64, error) { return 1 << 40, nil }
	if out2, err2 := f2.run(); err2 != nil || !out2.Applied {
		t.Fatalf("with headroom the apply must proceed: out=%+v err=%v", out2, err2)
	}
}

// TestTheStagedBinaryLandsBesideTheTargetAndIsCleanedUp is M4: the swap is a
// rename, and rename cannot cross a filesystem. Staging under state_dir made
// every apply fail with EXDEV on a node whose binary is in /usr/local/bin, or
// /opt, or a Docker volume, with $HOME elsewhere.
func TestTheStagedBinaryLandsBesideTheTargetAndIsCleanedUp(t *testing.T) {
	f := newApplyFixture(t)
	var stagedAt string
	f.deps.Probe = func(_ context.Context, binPath string) (string, error) {
		stagedAt = binPath
		return "observer " + fixtureTargetVersion, nil
	}
	// Fail at the swap so the staged file is still on disk at the end.
	f.deps.FS = failingRenameFS{}
	out, _ := f.run()
	if out.State != update.StateFailed || out.ErrorClass != update.ErrorSwap {
		t.Fatalf("outcome = %+v, want failed{swap} - the fixture was supposed to abort at step 6", out)
	}
	if stagedAt == "" {
		t.Fatal("the probe never ran")
	}
	if filepath.Dir(stagedAt) != filepath.Dir(f.exePath) {
		t.Errorf("staged at %q, want a sibling of %q - a cross-filesystem rename is EXDEV, every time",
			stagedAt, f.exePath)
	}
	if _, err := os.Stat(stagedAt); err == nil {
		t.Errorf("the staged binary was left at %q; state_dir retention never sweeps there", stagedAt)
	}
}

// failingRenameFS fails the swap's rename while letting the staging stats
// through, so the apply reaches step 6 and aborts there.
type failingRenameFS struct{}

func (failingRenameFS) Rename(string, string) error        { return errors.New("simulated cross-device link") }
func (failingRenameFS) Remove(n string) error              { return os.Remove(n) }
func (failingRenameFS) Stat(n string) (os.FileInfo, error) { return os.Stat(n) }

// TestADeterministicFailureIsBackedOffNotReRunEveryCycle is M2's third half.
//
// A hash mismatch, a bad signature, an unwritable target or a cross-device
// swap gives the SAME answer on the next tick — so re-running it every ten
// minutes re-downloads the archive and (before the manifest declared its
// schema) re-took a full VACUUM INTO of the whole database, forever. That is
// the automatic full-file rewrite class the 2026-08-26 disk audit forbids.
func TestADeterministicFailureIsBackedOffNotReRunEveryCycle(t *testing.T) {
	u := &updateRuntime{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	u.noteAutoApplyOutcome(applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorSwap})
	if !u.autoNextAttempt.After(time.Now()) {
		t.Fatal("a deterministic failure was not backed off; the loop would re-run it every cycle")
	}
	first := u.autoNextAttempt
	u.noteAutoApplyOutcome(applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorSwap})
	if !u.autoNextAttempt.After(first) {
		t.Error("the backoff did not grow on a repeat failure")
	}

	// A TRANSIENT class must not back off: a failed fetch or a busy node is
	// exactly what the plain cadence is for.
	u.noteAutoApplyOutcome(applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorDownload})
	if !u.autoNextAttempt.IsZero() {
		t.Error("a transient download failure was backed off")
	}

	// And any non-failure clears it, so a fixed manifest re-arms at once.
	u.noteAutoApplyOutcome(applyOutcome{State: update.StateFailed, ErrorClass: update.ErrorHash})
	u.noteAutoApplyOutcome(applyOutcome{State: update.StateAvailable, Deferred: true, Reason: update.ReasonWindow})
	if !u.autoNextAttempt.IsZero() || u.autoFailCount != 0 {
		t.Error("a deferred (window) outcome left the node backed off")
	}
}

// TestAnUnverifiableSignatureSchemeBlocksRatherThanPassing is L5.
//
// The manifest vocabulary is now exactly the one scheme anything verifies
// (update.SigTypeEd25519), so a document naming another one does not validate
// in the first place. This is the SECOND line of that defence, and it is the
// one that matters at apply time: an apply can run from a manifest cached in
// update_state, so the scheme is re-checked HERE against what
// verifyVendorSignature actually performs. CANNOT-verify is
// blocked{unsigned_artifact}, not a signature failure: an admin must be able
// to tell "this agent cannot check that scheme" from "the signature is wrong".
func TestAnUnverifiableSignatureSchemeBlocksRatherThanPassing(t *testing.T) {
	f := newApplyFixture(t)
	// A scheme that was once spellable and never verifiable.
	const retiredScheme = "cosign-bundle"
	f.opts.Artifact.UpstreamSigType = retiredScheme
	f.opts.Manifest.Artifacts[0].UpstreamSigType = retiredScheme
	f.deps.VerifyVendorSignature = verifyVendorSignature // the REAL one

	out, err := f.run()
	if err != nil {
		t.Fatalf("a cannot-verify is a defer, not an error: %v", err)
	}
	if out.State != update.StateBlocked || out.Reason != update.ReasonUnsignedArtifact {
		t.Fatalf("outcome = %+v, want blocked{unsigned_artifact}", out)
	}
	if got := f.installedBinary(); !strings.Contains(got, "OLD") {
		t.Fatal("a mislabelled signature scheme reached the swap")
	}
}
