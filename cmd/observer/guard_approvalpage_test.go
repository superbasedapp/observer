package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestApprovalPageHiddenLookup pins CG-16's boundary: the guard is told the
// Security page is hidden exactly when this machine's governance hides it
// (the managed default, or an org directive), never on an individual node,
// and a store that cannot be opened keeps the old texts.
func TestApprovalPageHiddenLookup(t *testing.T) {
	st, _ := openTestStore(t)
	cases := []struct {
		name string
		eff  govern.Effective
		open storeOpener
		want bool
	}{
		{"individual node", govern.Effective{}, storeOpenerFor(st), false},
		{"managed node, default", govern.Effective{Managed: true}, storeOpenerFor(st), true},
		{"managed node, org shows Security", govern.Effective{Managed: true, Active: true, VisibleSections: []string{"security"}}, storeOpenerFor(st), false},
		{"individual node, org hides Security", govern.Effective{Active: true, HiddenSections: []string{"security"}}, storeOpenerFor(st), true},
		{"store cannot be opened", govern.Effective{Managed: true}, func(context.Context) (*store.Store, func(), error) {
			return nil, nil, errors.New("locked")
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := approvalPageEffective
			t.Cleanup(func() { approvalPageEffective = prev })
			calls := 0
			approvalPageEffective = func(context.Context, config.Config, *store.Store, *slog.Logger) govern.Effective {
				calls++
				return tc.eff
			}
			fn := approvalPageHiddenLookup(config.Config{}, tc.open, nil)
			if got := fn(); got != tc.want {
				t.Fatalf("hidden = %v, want %v", got, tc.want)
			}
			if got := fn(); got != tc.want {
				t.Fatalf("second call: hidden = %v, want %v", got, tc.want)
			}
			if calls > 1 {
				t.Fatalf("governance resolved %d times; the answer is cached", calls)
			}
		})
	}
	if approvalPageHiddenLookup(config.Config{}, nil, nil) != nil {
		t.Fatal("no store opener must wire no lookup")
	}
}

// TestApprovalPageHiddenLookupUnenrolledStore runs the real resolver over a
// fresh, never-enrolled database: nothing is hidden.
func TestApprovalPageHiddenLookupUnenrolledStore(t *testing.T) {
	st, _ := openTestStore(t)
	if approvalPageHiddenLookup(config.Config{}, storeOpenerFor(st), nil)() {
		t.Fatal("an unenrolled node reported the Security page hidden")
	}
}
