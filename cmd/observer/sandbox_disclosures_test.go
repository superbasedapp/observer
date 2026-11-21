//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestSandboxDisclosureRows walks the table, one case per row: each row's
// id and mode select exactly that row's sentence.
func TestSandboxDisclosureRows(t *testing.T) {
	fallbacks := map[sandboxbackend.Disclosure]int{}
	for i, r := range sandboxDisclosureRows {
		// A mode-specific row answers for its mode; the one fallback row
		// of an id answers for a row with no gateway ("").
		if got := sandboxDisclosureText(r.id, r.mode); got != r.text {
			t.Errorf("row %d (%s, %q): got %q", i, r.id, r.mode, got)
		}
		if r.mode == "" {
			fallbacks[r.id]++
		}
		if strings.ContainsAny(r.text, "\u2013\u2014") {
			t.Errorf("row %d carries an en or em dash", i)
		}
	}
	for id, n := range fallbacks {
		if n != 1 {
			t.Errorf("%s has %d fallback rows, want 1", id, n)
		}
	}
}

// TestEveryRegistryDisclosureHasText: every disclosure a registry row
// declares has a sentence for every gateway mode and for none.
func TestEveryRegistryDisclosureHasText(t *testing.T) {
	modes := append([]vocab.GatewayMode{""}, vocab.GatewayModes()...)
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		for _, d := range row.Discloses {
			for _, m := range modes {
				if sandboxDisclosureText(d, m) == "" {
					t.Errorf("row %s discloses %s with no sentence for gateway mode %q", id, d, m)
				}
			}
		}
	}
}
