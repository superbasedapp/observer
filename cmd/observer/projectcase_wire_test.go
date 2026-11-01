package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestMergeCaseDuplicateProjectsAtStartLogsRootKeyed (WINNODE2 merge, audit
// M1): the daemon-start fold logs, per table, the root-keyed rows it left on
// the old spelling, so a guard approval or a security record that stops
// matching after the fold can be traced.
func TestMergeCaseDuplicateProjectsAtStartLogsRootKeyed(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	const keep, dup = `C:\Users\developer\projects\payments-api`, `c:\Users\developer\projects\payments-api`
	for _, root := range []string{keep, dup} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO projects (root_path, created_at, root_path_hash) VALUES (?, '2026-10-28T13:00:00Z', ?)`, root, hash(root)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sec_change_consent (project_root_hash, root_path) VALUES (?, ?)`, hash(dup), dup); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	mergeCaseDuplicateProjectsAtStart(ctx, database, slog.New(slog.NewTextHandler(&logs, nil)))
	out := logs.String()
	for _, want := range []string{"folded a Windows project row", "root_keyed_left_on_old_spelling", "sec_change_consent.project_root_hash:1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the fold log lacks %q:\n%s", want, out)
		}
	}
}
