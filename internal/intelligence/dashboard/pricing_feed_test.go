package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// GET /api/config/pricing reports a standalone node's synced feed rows as
// source "feed" (not "org"), with the feed version + per-model economics, while
// the engine composes them through the same org-rows input.
func TestConfigPricingReportsFeedSource(t *testing.T) {
	const model = "claude-opus-4-8"
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	// Persist a verified feed envelope (no enrolment => standalone => feed active).
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   12,
		KeyID:         pricingfeed.PricingFeedKeyIDV1,
		Digest:        "dig",
		Signature:     "sig",
		Rows: []pricingfeed.Row{{
			PricingPolicyRow: orgcontract.PricingPolicyRow{
				Model: model, InputPerMTok: orgcontract.Rate(7), OutputPerMTok: orgcontract.Rate(35), Source: "list",
			},
			Economics: &pricingfeed.Economics{
				CacheMode:        pricingfeed.CacheModeExplicit,
				ReasoningBilling: pricingfeed.ReasoningBillingOutputRate,
			},
		}},
	}
	if err := store.New(database).SavePricingFeed(context.Background(), env, "verified"); err != nil {
		t.Fatalf("SavePricingFeed: %v", err)
	}

	// Compose the feed rows into the engine NON-authoritatively (the standalone
	// ladder), exactly as the cost-engine loader does.
	feedRows := cost.OrgRows{
		Version: 12,
		Rows: []cost.OrgPrice{{
			Model:   model,
			Pricing: cost.Pricing{Input: 7, Output: 35},
			Set:     cost.OrgPriceSet{Input: true, Output: true},
		}},
	}
	engine := cost.NewEngine(config.IntelligenceConfig{}, cost.WithOrgRows(func() (cost.OrgRows, bool) { return feedRows, true }))

	server, err := New(Options{DB: database, CostEngine: engine})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/pricing", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Models map[string]struct {
			Source    string `json:"source"`
			Economics *struct {
				CacheMode        string `json:"cache_mode"`
				ReasoningBilling string `json:"reasoning_billing"`
			} `json:"economics"`
		} `json:"models"`
		FeedVersion int64 `json:"feed_version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rr.Body.String())
	}
	if resp.FeedVersion != 12 {
		t.Errorf("feed_version = %d, want 12", resp.FeedVersion)
	}
	m, ok := resp.Models[model]
	if !ok {
		t.Fatalf("model %q missing from the effective table", model)
	}
	if m.Source != "feed" {
		t.Errorf("source = %q, want feed", m.Source)
	}
	if m.Economics == nil || m.Economics.CacheMode != pricingfeed.CacheModeExplicit {
		t.Errorf("economics = %+v, want the feed-carried cache mode", m.Economics)
	}
}

// TestConfigPricingIncludesPeakVariant pins the peak/off-peak Phase 1
// slice D display contract: GET /api/config/pricing's per-model row
// EMBEDS cost.Pricing directly (pricedModel{cost.Pricing; Source;
// Economics}), so a model carrying a Peak variant — today only
// deepseek-v4-pro — serializes its `peak` object with NO extra Go
// wiring. This is the "confirm, don't re-plumb" check: the endpoint
// needs no production change for the dashboard's Settings -> Pricing
// table to render the 2x peak rates + the peak schedule.
func TestConfigPricingIncludesPeakVariant(t *testing.T) {
	const model = "deepseek-v4-pro"
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	engine := cost.NewEngine(config.IntelligenceConfig{})
	server, err := New(Options{DB: database, CostEngine: engine})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config/pricing", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Models map[string]struct {
			Input  float64 `json:"input"`
			Output float64 `json:"output"`
			Source string  `json:"source"`
			Peak   *struct {
				Input     float64 `json:"input"`
				Output    float64 `json:"output"`
				CacheRead float64 `json:"cache_read"`
				Schedule  struct {
					Windows []struct {
						Days     []int  `json:"days"`
						StartUTC string `json:"start_utc"`
						EndUTC   string `json:"end_utc"`
					} `json:"windows"`
				} `json:"schedule"`
			} `json:"peak"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body %s", err, rr.Body.String())
	}

	m, ok := resp.Models[model]
	if !ok {
		t.Fatalf("model %q missing from the effective table", model)
	}
	if m.Input != 0.66 || m.Output != 1.98 {
		t.Fatalf("off-peak base rates = %+v, want input=0.66 output=1.98", m)
	}
	if m.Peak == nil {
		t.Fatalf("peak object missing from %s's effective pricing row", model)
	}
	// Peak is EXACTLY 2x the off-peak base, per the deepseek-v4-pro seed row.
	if m.Peak.Input != 1.32 || m.Peak.Output != 3.96 || m.Peak.CacheRead != 0.044 {
		t.Errorf("peak rates = %+v, want input=1.32 output=3.96 cache_read=0.044", m.Peak)
	}
	if len(m.Peak.Schedule.Windows) != 2 {
		t.Fatalf("peak schedule windows = %d, want 2", len(m.Peak.Schedule.Windows))
	}
	for _, w := range m.Peak.Schedule.Windows {
		if len(w.Days) != 5 {
			t.Errorf("window %+v: want 5 weekdays (Mon-Fri)", w)
		}
		if w.StartUTC == "" || w.EndUTC == "" {
			t.Errorf("window %+v: missing start/end", w)
		}
	}
}
