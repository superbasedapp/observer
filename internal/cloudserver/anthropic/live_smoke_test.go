package anthropic_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/anthropic"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/prove"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// liveSmokeFlag gates the ONE real Anthropic call this package can make. It is
// off in every normal run (and in CI): the test skips unless it is "1".
const liveSmokeFlag = "SBCI_ANTHROPIC_LIVE_SMOKE"

// liveKeyVars are the variables the smoke reads the key from, in order. The
// key is passed by reference (e.g. `docker run --env-file <path>`); this test
// never prints it.
var liveKeyVars = []string{"SBCI_ANTHROPIC_API_KEY", "ANTHROPIC_KEY"}

// TestLiveSmokeOneHaikuCall makes EXACTLY ONE Messages API call to
// claude-haiku-5-5 through the production client, with the production Luna
// system prompt, the production strict result schema and one compiled-in
// synthetic prove fixture as evidence (no developer data), then runs the
// production post-call stage (normalize, scrub, ground). It proves the whole
// provider path: auth, the wire shape, structured output acceptance of the real
// schema, and that the answer passes the real validation.
func TestLiveSmokeOneHaikuCall(t *testing.T) {
	if os.Getenv(liveSmokeFlag) != "1" {
		t.Skipf("live smoke off: set %s=1 and provide the key by reference in %v", liveSmokeFlag, liveKeyVars)
	}
	var key string
	for _, v := range liveKeyVars {
		// `docker run --env-file` keeps quotes literally; tolerate a quoted value.
		if k := strings.Trim(strings.TrimSpace(os.Getenv(v)), `"'`); k != "" {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatalf("%s=1 but none of %v is set", liveSmokeFlag, liveKeyVars)
	}

	fx := prove.Catalog()[0]
	evidence, err := fx.UploadBytes()
	if err != nil {
		t.Fatalf("fixture %s: %v", fx.Name, err)
	}
	env, err := fx.Envelope()
	if err != nil {
		t.Fatalf("fixture %s envelope: %v", fx.Name, err)
	}
	prompt, err := jobs.BuildLunaPrompt(evidence)
	if err != nil {
		t.Fatalf("BuildLunaPrompt: %v", err)
	}
	route := store.RouteInfo{
		RouteID: "session_enrichment.claude-haiku-5-5.v1", Deployment: anthropic.DefaultModel,
		Dialect: string(inference.DialectAnthropicMessages), Endpoint: anthropic.DefaultBaseURL,
		APIVersion: anthropic.APIVersion, MaxOutputTokens: 4096,
	}
	req := jobs.BuildLunaRequest(route, key, prompt)
	req.Timeout = 90 * time.Second

	start := time.Now()
	res, err := (&anthropic.Client{}).Complete(context.Background(), req)
	elapsed := time.Since(start)
	if err != nil {
		// The error text carries the provider status + error document, never
		// the key (the SDK error body is the provider's response).
		t.Fatalf("live call failed after %s: %v", elapsed.Round(time.Millisecond), err)
	}
	t.Logf("live call: model=%s finish=%s elapsed=%s", res.Model, res.FinishReason, elapsed.Round(time.Millisecond))
	t.Logf("usage: input=%d cache_read=%d cache_write=%d output=%d (tokens_in=%d tokens_out=%d)",
		res.Usage.Input, res.Usage.CacheRead, res.Usage.CacheWrite, res.Usage.Output, res.TokensIn, res.TokensOut)

	cleaned, rejection := jobs.ProcessLunaCompletion(res.Content, cloudcontract.AllowedEvidenceRefs(env))
	if rejection != "" {
		t.Fatalf("the production post-call stage rejected the answer: %s (finish=%s, %d content bytes)",
			jobs.InvalidOutputDetail(res, rejection), res.FinishReason, len(res.Content))
	}
	t.Logf("result: title=%q confidence=%s tags=%d refs=%d", cleaned.Title.String(), cleaned.Confidence,
		len(cleaned.TaxonomyTags), len(cleaned.EvidenceRefs))
}
