package db_test

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
)

// TestMigration42AnthropicRoute pins migration 0042 on a FRESH database: the
// Claude Haiku 5.5 route lands inactive, unbound and unpriced (the bind command
// stamps the price from the pricing table), the dialect CHECK accepts
// anthropic_messages and still refuses anything else, the per-route kill
// switch exists (default off), and the earlier routes are untouched.
func TestMigration42AnthropicRoute(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	var (
		feature, deployment, dialect, priceVersion, endpoint, arm string
		routeVersion, promptVersion                               int64
		active, pinned                                            bool
		maxOut                                                    int
		inPrice, outPrice                                         float64
	)
	if err := pool.QueryRow(ctx,
		`SELECT feature, deployment, dialect, route_version, prompt_version, price_version, active, plan_pinned,
		        max_output_tokens, input_price_per_mtok, output_price_per_mtok, endpoint, arm_resource_id
		   FROM route_registry WHERE route_id = 'session_enrichment.claude-haiku-5-5.v1'`).Scan(
		&feature, &deployment, &dialect, &routeVersion, &promptVersion, &priceVersion, &active, &pinned,
		&maxOut, &inPrice, &outPrice, &endpoint, &arm); err != nil {
		t.Fatalf("read the 0042 route: %v", err)
	}
	if feature != "session_enrichment" || deployment != "claude-haiku-5-5" || dialect != "anthropic_messages" {
		t.Fatalf("route = %s/%s/%s", feature, deployment, dialect)
	}
	if routeVersion != 3 || promptVersion != 1 || pinned {
		t.Fatalf("route_version=%d prompt_version=%d plan_pinned=%v, want 3/1/false", routeVersion, promptVersion, pinned)
	}
	if active || endpoint != "" || arm != "" {
		t.Fatalf("route must ship inactive and unbound: active=%v endpoint=%q arm=%q", active, endpoint, arm)
	}
	if inPrice != 0 || outPrice != 0 || priceVersion != "unset" {
		t.Fatalf("route must ship unpriced (the bind command stamps it from the pricing table): %v/%v %q", inPrice, outPrice, priceVersion)
	}
	if maxOut != 4096 {
		t.Fatalf("max_output_tokens = %d, want 4096", maxOut)
	}

	var ksActive bool
	if err := pool.QueryRow(ctx,
		`SELECT active FROM kill_switches WHERE scope='route' AND key='session_enrichment.claude-haiku-5-5.v1'`).Scan(&ksActive); err != nil || ksActive {
		t.Fatalf("per-route kill switch: active=%v err=%v, want a row, off", ksActive, err)
	}

	// The CHECK still refuses an unknown dialect.
	if _, err := pool.Exec(ctx,
		`UPDATE route_registry SET dialect = 'openai_responses' WHERE route_id = 'session_enrichment.claude-haiku-5-5.v1'`); err == nil {
		t.Fatal("the dialect CHECK accepted an unknown dialect")
	}

	// Earlier routes are untouched: luna.v1 still the active seed, gpt-6-luna
	// still inactive at version 2.
	var lunaActive, gpt6Active bool
	var lunaDialect string
	if err := pool.QueryRow(ctx, `SELECT active, dialect FROM route_registry WHERE route_id='session_enrichment.luna.v1'`).Scan(&lunaActive, &lunaDialect); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT active FROM route_registry WHERE route_id='session_enrichment.gpt-6-luna.v1'`).Scan(&gpt6Active); err != nil {
		t.Fatal(err)
	}
	if !lunaActive || lunaDialect != "chat_completions" || gpt6Active {
		t.Fatalf("earlier routes moved: luna active=%v dialect=%s, gpt-6-luna active=%v", lunaActive, lunaDialect, gpt6Active)
	}

	// No Azure-only extension is required by the lineage: the only extension a
	// fresh database carries beyond plpgsql is btree_gist (stock contrib).
	rows, err := pool.Query(ctx, `SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY extname`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var exts []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		exts = append(exts, n)
	}
	if len(exts) != 1 || exts[0] != "btree_gist" {
		t.Fatalf("extensions on a fresh database = %v, want exactly [btree_gist]", exts)
	}
}
