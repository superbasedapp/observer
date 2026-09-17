package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func seedExport(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "exp.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	_, err = store.New(database).Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sA", ProjectRoot: root,
		Timestamp: base, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "x.go", Success: true,
	}, {
		SourceFile: "f", SourceEventID: "e2", SessionID: "sA", ProjectRoot: root,
		Timestamp: base.Add(time.Second), Tool: models.ToolClaudeCode,
		ActionType: models.ActionRunCommand, Target: "go test",
		Success: false, ErrorMessage: "boom",
	}}, nil, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func TestExport_ActionsJSONL(t *testing.T) {
	dbPath := seedExport(t)
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var buf bytes.Buffer
	if err := runExport(context.Background(), database, &buf, exportOptions{
		Format: "json", Table: "actions",
	}); err != nil {
		t.Fatalf("runExport: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), buf.String())
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("parse first line: %v", err)
	}
	if row["action_type"] != "read_file" {
		t.Errorf("first row action_type: %v", row["action_type"])
	}
	if row["target"] != "x.go" {
		t.Errorf("first row target: %v", row["target"])
	}
}

func TestExport_ActionsCSV(t *testing.T) {
	dbPath := seedExport(t)
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var buf bytes.Buffer
	if err := runExport(context.Background(), database, &buf, exportOptions{
		Format: "csv", Table: "actions",
	}); err != nil {
		t.Fatalf("runExport: %v", err)
	}
	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(rows) != 3 { // header + 2 rows
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0][0] != "id" {
		t.Errorf("header[0]: %v", rows[0])
	}
}

func TestExport_UnknownTable(t *testing.T) {
	dbPath := seedExport(t)
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	err = runExport(context.Background(), database, new(bytes.Buffer), exportOptions{
		Format: "json", Table: "bogus",
	})
	if err == nil || !strings.Contains(err.Error(), "not in") {
		t.Errorf("expected friendly error, got %v", err)
	}
}

func TestExport_SessionsJSONL(t *testing.T) {
	dbPath := seedExport(t)
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var buf bytes.Buffer
	if err := runExport(context.Background(), database, &buf, exportOptions{
		Format: "json", Table: "sessions",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"id":"sA"`) {
		t.Errorf("missing session row: %s", buf.String())
	}
}
