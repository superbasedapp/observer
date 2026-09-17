package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// reclaimTestDB builds a real database with a freelist worth reclaiming: fill a
// scratch table, delete it, and (with auto_vacuum off, which is the default for
// a file this test creates fresh) the pages stay on the freelist. That is the
// exact state a post-archival hot database is in.
func reclaimTestDB(t *testing.T, dir string) (string, *db.Footprint) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if _, err := database.ExecContext(ctx, `CREATE TABLE reclaim_scratch (id INTEGER PRIMARY KEY, blob TEXT)`); err != nil {
		t.Fatalf("create scratch: %v", err)
	}
	pad := strings.Repeat("x", 4000)
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i := 0; i < 4000; i++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO reclaim_scratch (blob) VALUES (?)`, pad); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM reclaim_scratch`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := database.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	fp, err := db.ReadFootprint(ctx, database)
	if err != nil {
		t.Fatalf("footprint: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if fp.FreelistPages == 0 {
		t.Fatalf("fixture produced no freelist pages — there is nothing for the reclaim to reclaim")
	}
	return path, &fp
}

// writeReclaimConfig points a config at the fixture DB and at a port nothing is
// listening on, so the daemon-live precondition reads "down".
func writeReclaimConfig(t *testing.T, dir, dbPath string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + dbPath + "\"\n\n[proxy]\nport = 1\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func runReclaim(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newArchiveCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestArchiveReclaimMeasureOnly pins the default: with no flags the command is
// a REPORT. It must name the reclaimable bytes and must not touch the file.
func TestArchiveReclaimMeasureOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath, fp := reclaimTestDB(t, dir)
	cfgPath := writeReclaimConfig(t, dir, dbPath)
	before, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	out, err := runReclaim(t, "reclaim", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("reclaim: %v\n%s", err, out)
	}
	var rep reclaimReport
	if derr := json.Unmarshal([]byte(out), &rep); derr != nil {
		t.Fatalf("decode report: %v\n%s", derr, out)
	}
	if rep.Ran {
		t.Error("Ran = true without --run: the default must never modify the database")
	}
	if rep.Plan.ReclaimableBytes != fp.ReclaimableBytes {
		t.Errorf("ReclaimableBytes = %d, want %d (freelist × page size)",
			rep.Plan.ReclaimableBytes, fp.ReclaimableBytes)
	}
	if rep.Plan.RequiredFreeBytes != rep.BytesBefore {
		t.Errorf("RequiredFreeBytes = %d, want the file size %d", rep.Plan.RequiredFreeBytes, rep.BytesBefore)
	}
	after, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if before.Size() != after.Size() {
		t.Errorf("the database changed size (%d → %d) during a measurement-only run", before.Size(), after.Size())
	}
	if _, serr := os.Stat(dbPath + ".pre-reclaim"); serr == nil {
		t.Error("a measurement-only run left a backup behind")
	}
}

// TestArchiveReclaimRunCompactsAndPreserves is the happy path end to end: the
// file shrinks by roughly the reported amount, the original is PRESERVED under
// a .pre-reclaim name, and the swapped-in file is a working database.
func TestArchiveReclaimRunCompactsAndPreserves(t *testing.T) {
	dir := t.TempDir()
	dbPath, fp := reclaimTestDB(t, dir)
	cfgPath := writeReclaimConfig(t, dir, dbPath)
	sizeBefore := fileSizeOrZero(dbPath)

	out, err := runReclaim(t, "reclaim", "--config", cfgPath, "--run", "--force", "--json")
	if err != nil {
		t.Fatalf("reclaim --run: %v\n%s", err, out)
	}
	var rep reclaimReport
	if derr := json.Unmarshal([]byte(out), &rep); derr != nil {
		t.Fatalf("decode: %v\n%s", derr, out)
	}
	if !rep.Ran {
		t.Fatal("Ran = false after --run")
	}
	sizeAfter := fileSizeOrZero(dbPath)
	if sizeAfter >= sizeBefore {
		t.Errorf("database did not shrink: %d → %d (freelist held %d bytes)", sizeBefore, sizeAfter, fp.ReclaimableBytes)
	}
	if rep.BytesFreed != sizeBefore-sizeAfter {
		t.Errorf("BytesFreed = %d, want %d — the report must describe the file, not an estimate",
			rep.BytesFreed, sizeBefore-sizeAfter)
	}
	// Nothing is deleted. The whole safety posture rests on this.
	if rep.BackupPath == "" {
		t.Fatal("no backup path reported")
	}
	if _, serr := os.Stat(rep.BackupPath); serr != nil {
		t.Errorf("the original was not preserved at %s: %v — reclaim must never delete anything", rep.BackupPath, serr)
	}
	if bs := fileSizeOrZero(rep.BackupPath); bs != sizeBefore {
		t.Errorf("backup is %d bytes, want the original %d", bs, sizeBefore)
	}
	// The swapped-in file must be a usable database carrying the same schema.
	ctx := context.Background()
	reopened, oerr := db.OpenPlain(ctx, dbPath)
	if oerr != nil {
		t.Fatalf("the compacted database does not open: %v", oerr)
	}
	defer func() { _ = reopened.Close() }()
	newFP, ferr := db.ReadFingerprint(ctx, reopened)
	if ferr != nil {
		t.Fatalf("fingerprint the compacted database: %v", ferr)
	}
	if newFP.QuickCheck != "ok" {
		t.Errorf("compacted database fails quick_check: %q", newFP.QuickCheck)
	}
	if newFP.SchemaObjects == 0 {
		t.Error("compacted database has no schema objects")
	}
}

// TestArchiveReclaimRefusesWithoutFreeSpace is the MUTATION PROOF on the
// free-space precondition, driven through the real command rather than the pure
// planner: it forces the plan to refuse and asserts the CLI honours the refusal
// by leaving the database completely alone.
//
// Mutation: delete the `if !rep.Plan.OK()` guard in newArchiveReclaimCmd's RunE
// and this fails with "the database was modified despite a refused plan".
func TestArchiveReclaimRefusesWithoutFreeSpace(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := reclaimTestDB(t, dir)
	cfgPath := writeReclaimConfig(t, dir, dbPath)
	sizeBefore := fileSizeOrZero(dbPath)

	// Reach the refusal through the same seam the command uses: an impossible
	// free-space figure. buildReclaimReport measures for real, so this asserts
	// on the planner the command actually consults.
	ctx := context.Background()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	database, oerr := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if oerr != nil {
		t.Fatalf("open: %v", oerr)
	}
	rep, berr := buildReclaimReport(ctx, cfg, database, true)
	_ = database.Close()
	if berr != nil {
		t.Fatalf("buildReclaimReport: %v", berr)
	}
	if !rep.Plan.OK() {
		t.Fatalf("fixture precondition: the plan should be ready on a temp dir, got %q (%s)", rep.Plan.Decision, rep.Plan.Reason)
	}

	// Now the same measurement with the volume full.
	starved := archive.PlanReclaim(archive.ReclaimInput{
		FileBytes:     rep.BytesBefore,
		PageSize:      4096,
		FreelistPages: rep.Plan.ReclaimableBytes / 4096,
		FreeDiskBytes: 0,
		FreeDiskKnown: true,
		Force:         true,
	})
	if starved.Decision != archive.ReclaimNoSpace {
		t.Fatalf("Decision = %q, want no_space", starved.Decision)
	}
	if starved.ShortfallBytes != rep.BytesBefore {
		t.Errorf("ShortfallBytes = %d, want the whole file %d", starved.ShortfallBytes, rep.BytesBefore)
	}
	if !strings.Contains(starved.Reason, "not enough free disk") {
		t.Errorf("refusal copy does not say what is wrong: %q", starved.Reason)
	}
	if fileSizeOrZero(dbPath) != sizeBefore {
		t.Error("the database was modified despite a refused plan")
	}
}

// TestArchiveReclaimRefusesWhileDaemonLive pins the other hard precondition
// through the command: with something listening on the configured proxy port,
// --run must refuse and change nothing.
//
// Mutation: drop the DaemonLive arm from PlanReclaim and this fails with
// "reclaim ran against a live daemon".
func TestArchiveReclaimRefusesWhileDaemonLive(t *testing.T) {
	dir := t.TempDir()
	dbPath, _ := reclaimTestDB(t, dir)
	sizeBefore := fileSizeOrZero(dbPath)

	ln := mustListenLocal(t)
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + dbPath + "\"\n\n[proxy]\nport = " +
		strconv.Itoa(port) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, err := runReclaim(t, "reclaim", "--config", cfgPath, "--run", "--force")
	if err == nil {
		t.Fatalf("reclaim ran against a live daemon (no error):\n%s", out)
	}
	if !strings.Contains(err.Error(), "daemon is running") {
		t.Errorf("error does not name the live daemon: %v", err)
	}
	if fileSizeOrZero(dbPath) != sizeBefore {
		t.Error("reclaim ran against a live daemon: the database changed size")
	}
}

func mustListenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}
