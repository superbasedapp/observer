package db_test

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
)

// TestMigration45And46OpenAICompatibleRoute pins migrations 0045 and 0046 on a
// FRESH database: the gpt-oss-120b route lands inactive, unbound and unpriced;
// the old dialect CHECK is gone and the widened route_registry_dialect_check_v2
// is validated, accepts openai_compatible and still refuses anything else; the
// per-route kill switch exists (default off); the Haiku route is untouched.
func TestMigration45And46OpenAICompatibleRoute(t *testing.T) {
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
		   FROM route_registry WHERE route_id = 'session_enrichment.gpt-oss-120b.v1'`).Scan(
		&feature, &deployment, &dialect, &routeVersion, &promptVersion, &priceVersion, &active, &pinned,
		&maxOut, &inPrice, &outPrice, &endpoint, &arm); err != nil {
		t.Fatalf("read the 0046 route: %v", err)
	}
	if feature != "session_enrichment" || deployment != "gpt-oss-120b" || dialect != "openai_compatible" {
		t.Fatalf("route = %s/%s/%s", feature, deployment, dialect)
	}
	if routeVersion != 4 || promptVersion != 1 || pinned {
		t.Fatalf("route_version=%d prompt_version=%d plan_pinned=%v, want 4/1/false", routeVersion, promptVersion, pinned)
	}
	if active || endpoint != "" || arm != "" {
		t.Fatalf("route must ship inactive and unbound: active=%v endpoint=%q arm=%q", active, endpoint, arm)
	}
	if inPrice != 0 || outPrice != 0 || priceVersion != "unset" || maxOut != 4096 {
		t.Fatalf("price %v/%v %q, max_output_tokens %d; want unpriced and 4096", inPrice, outPrice, priceVersion, maxOut)
	}

	var ksActive bool
	if err := pool.QueryRow(ctx,
		`SELECT active FROM kill_switches WHERE scope='route' AND key='session_enrichment.gpt-oss-120b.v1'`).Scan(&ksActive); err != nil || ksActive {
		t.Fatalf("per-route kill switch: active=%v err=%v, want a row, off", ksActive, err)
	}

	// One dialect CHECK remains: v2, validated.
	rows, err := pool.Query(ctx,
		`SELECT conname, convalidated FROM pg_constraint
		  WHERE conrelid = 'route_registry'::regclass AND conname LIKE 'route_registry_dialect_check%' ORDER BY conname`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		var ok bool
		if err := rows.Scan(&n, &ok); err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("constraint %s is not validated", n)
		}
		names = append(names, n)
	}
	rows.Close()
	if len(names) != 1 || names[0] != "route_registry_dialect_check_v2" {
		t.Fatalf("dialect constraints = %v, want exactly [route_registry_dialect_check_v2]", names)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE route_registry SET dialect = 'openai_responses' WHERE route_id = 'session_enrichment.gpt-oss-120b.v1'`); err == nil {
		t.Fatal("the dialect CHECK accepted an unknown dialect")
	}

	var haikuDialect string
	var haikuActive bool
	if err := pool.QueryRow(ctx, `SELECT active, dialect FROM route_registry WHERE route_id='session_enrichment.claude-haiku-5-5.v1'`).Scan(&haikuActive, &haikuDialect); err != nil {
		t.Fatal(err)
	}
	if haikuActive || haikuDialect != "anthropic_messages" {
		t.Fatalf("the Haiku route moved: active=%v dialect=%s", haikuActive, haikuDialect)
	}
}
