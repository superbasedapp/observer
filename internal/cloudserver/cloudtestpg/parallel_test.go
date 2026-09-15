package cloudtestpg

import (
	"context"
	"fmt"
	"testing"
)

// TestNewDBParallelNoRoleRace stresses the exact contention Task-3 is about:
// many fresh test databases migrating at once all run 0001_roles.sql, whose
// CREATE/ALTER ROLE touch the CLUSTER-GLOBAL pg_authid tuples, so concurrent
// migrators race and Postgres raises "tuple concurrently updated" (SQLSTATE
// XX000). NewDB fatals ("migrate …: gave up after N attempts") when the race
// wins, so this test goes red without the harness-side migration serialization.
//
// Parallel subtests reproduce the cross-database race inside ONE process (each
// subtest creates its own database; the roles they touch are shared), which is
// the same shape as `go test` running package binaries in parallel — just
// cheaper and deterministic to run on demand.
func TestNewDBParallelNoRoleRace(t *testing.T) {
	RequireDSN(t) // SKIPs loudly when no Postgres is configured.

	const n = 24
	for i := 0; i < n; i++ {
		i := i
		t.Run(fmt.Sprintf("db-%02d", i), func(t *testing.T) {
			t.Parallel()
			pool := NewDB(t)
			var one int
			if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil {
				t.Fatalf("sanity query on fresh db: %v", err)
			}
		})
	}
}
