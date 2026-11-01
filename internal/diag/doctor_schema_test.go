package diag

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/migplan"
)

// TestCheckSchemaReportsAPendingLowerStep pins that db.schema reads the
// runner's plan (T-979): a current database is OK, and one missing the
// per-step record of a step below its version warns and names that step.
func TestCheckSchemaReportsAPendingLowerStep(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	if c := checkSchema(ctx, database); c.Status != StatusOK {
		t.Fatalf("current database: %+v", c)
	}
	if _, err := database.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, migplan.StepKey(2)); err != nil {
		t.Fatal(err)
	}
	c := checkSchema(ctx, database)
	if c.Status != StatusWarn || !strings.Contains(c.Message, "1 migration(s) pending (2)") {
		t.Fatalf("missing step 2: %+v", c)
	}
}
