package modal

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestCreateRefusesADenyItCannotCarry (SBXD-7): the vendor's create takes no
// deny rule, so the table never asks for one, and a create that carries one
// anyway is refused before any call rather than made as an open box.
func TestCreateRefusesADenyItCannotCarry(t *testing.T) {
	spec := sandboxremote.BoxSpec{RunID: "run-1", TimeoutSeconds: 600, Tier: vocab.TierInternet, DenyCIDRs: []string{"10.0.0.0/8"}}
	if _, err := (&Client{}).Create(context.Background(), spec); !errors.Is(err, sandboxremote.ErrDenyNotRenderable) {
		t.Fatalf("a deny this vendor cannot carry: %v", err)
	}
}
