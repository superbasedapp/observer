package cost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func TestTableCarriesEnrollmentBindingAndFenceRejectsStalePublication(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	witness := PricingDocumentWitness{Known: true, Present: true, SHA256: "pricing-document-hash"}
	e.SetOrgRows([]OrgPrice{{
		Model:   "fixture-model",
		Pricing: Pricing{Input: 1, Output: 2},
		Set:     OrgPriceSet{Input: true, Output: true},
	}}, 1, true, "enrollment-one")
	expected := e.Table()
	if expected == nil || expected.EnrollmentBinding() != "enrollment-one" {
		t.Fatalf("table binding = %q, want enrollment-one", expected.EnrollmentBinding())
	}
	e.SetOrgRowsWithWitness([]OrgPrice{{
		Model:   "fixture-model",
		Pricing: Pricing{Input: 1, Output: 2},
		Set:     OrgPriceSet{Input: true, Output: true},
	}}, 1, true, "enrollment-one", witness)
	expected = e.Table()
	if expected == nil || expected.PricingDocumentWitness() != witness {
		t.Fatalf("table pricing witness = %+v, want %+v", expected.PricingDocumentWitness(), witness)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	if err := e.WithPricingTable(ctx, expected, func() error {
		called = true
		if e.Table() != expected {
			t.Fatal("table changed while the pricing fence was held")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPricingTable: %v", err)
	}
	if !called {
		t.Fatal("pricing fence did not run its callback")
	}

	e.SetOrgRows(nil, 0, false, "enrollment-two")
	if err := e.WithPricingTable(ctx, expected, func() error { return nil }); !errors.Is(err, ErrPricingTableChanged) {
		t.Fatalf("stale pricing fence error = %v, want ErrPricingTableChanged", err)
	}
}

func TestWithPricingTableRequiresBoundedContext(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	expected := e.Table()
	if err := e.WithPricingTable(context.Background(), expected, func() error { return nil }); !errors.Is(err, ErrPricingTableDeadlineRequired) {
		t.Fatalf("unbounded context error = %v, want ErrPricingTableDeadlineRequired", err)
	}
	if err := e.WithPricingTable(nil, expected, func() error { return nil }); !errors.Is(err, ErrPricingTableDeadlineRequired) { //nolint:staticcheck // SA1012: deliberate invalid-input rejection test.
		t.Fatalf("nil context error = %v, want ErrPricingTableDeadlineRequired", err)
	}
}

func TestWithPricingTableFailsImmediatelyWhenPublisherIsBusy(t *testing.T) {
	e := NewEngine(config.IntelligenceConfig{})
	expected := e.Table()
	e.rebuildMu.Lock()
	defer e.rebuildMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	started := time.Now()
	err := e.WithPricingTable(ctx, expected, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrPricingTableChanged) {
		t.Fatalf("busy pricing fence error = %v, want ErrPricingTableChanged", err)
	}
	if called {
		t.Fatal("busy pricing fence ran its callback")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("busy pricing fence waited %s; TryLock must fail immediately", elapsed)
	}
}
