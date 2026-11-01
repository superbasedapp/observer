//go:build !sbo_omit_isolation && !sbo_omit_isolation_seal

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/execevidence"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// TestEvidenceSealOptIn: off with no [components] block and with a block
// that does not select it; on only when a block adds it; the rule governs
// isolation.seal only.
func TestEvidenceSealOptIn(t *testing.T) {
	cases := []struct {
		name string
		snap componentstate.Snapshot
		want bool
	}{
		{"no block", componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs()), false},
		{"a block without it", componentstate.Resolve(config.ComponentsConfig{Distro: "full"}, fullNodeIDs()), false},
		{"selected", componentstate.Resolve(config.ComponentsConfig{Distro: "full", Add: []string{"isolation", "isolation.seal"}}, fullNodeIDs()), true},
		{"removed", componentstate.Resolve(config.ComponentsConfig{Distro: "full", Add: []string{"isolation.seal"}, Remove: []string{"isolation.seal"}}, fullNodeIDs()), false},
	}
	for _, c := range cases {
		if got := evidenceSealSelected(c.snap); got != c.want {
			t.Errorf("%s: selected %v, want %v", c.name, got, c.want)
		}
		governs, active := evidenceSealOptIn(c.snap, evidenceSealComponent)
		if !governs || active != c.want {
			t.Errorf("%s: rule %v %v", c.name, governs, active)
		}
	}
	if governs, _ := evidenceSealOptIn(componentstate.Snapshot{}, "isolation"); governs {
		t.Error("the rule governs another component")
	}
}

// TestEvidenceSealKeyAndSealer: one key made and reused from the keystore,
// and the sealer's seal verifies over the digest.
func TestEvidenceSealKeyAndSealer(t *testing.T) {
	ks := &keystore.MemStore{}
	a, err := evidenceSealKey(ks)
	if err != nil {
		t.Fatal(err)
	}
	b, err := evidenceSealKey(ks)
	if err != nil || !a.Equal(b) || len(ks.Names()) != 1 {
		t.Fatalf("the key was not reused: %v %v", err, ks.Names())
	}
	digest := strings.Repeat("ab", 32)
	seal, ok := evidenceSealer(a)(context.Background(), digest)
	if !ok {
		t.Fatal("no seal")
	}
	if err := execevidence.VerifySeal(execevidence.Seal{KeyID: seal.KeyID, PublicKey: seal.PublicKey, Sig: seal.Sig}, digest); err != nil {
		t.Fatalf("the seal does not verify: %v", err)
	}
	if _, ok := evidenceSealer(a)(context.Background(), "not-a-digest"); ok {
		t.Fatal("sealed a non-digest")
	}
}

// TestEvidenceSealRegisterBackoffAfter404 (audit finding F6): a 404 from
// the org no longer stops the registration until a restart; it backs off,
// doubling from an hour to a day. A registered or an individual answer
// stops; any other failure keeps the fixed retry.
func TestEvidenceSealRegisterBackoffAfter404(t *testing.T) {
	if _, stop := evidenceSealNextWait(nil, 0); !stop {
		t.Fatal("a registered key kept registering")
	}
	if _, stop := evidenceSealNextWait(orgclient.ErrExecSealIndividual, 0); !stop {
		t.Fatal("an individual enrolment kept registering")
	}
	// A key the org revoked (R-017) is never accepted again; asking every
	// six hours would only repeat the refusal.
	if _, stop := evidenceSealNextWait(fmt.Errorf("wrapped: %w", orgclient.ErrExecSealKeyRevoked), 0); !stop {
		t.Fatal("a revoked key kept registering")
	}
	var waits []time.Duration
	prev := time.Duration(0)
	for i := 0; i < 7; i++ {
		w, stop := evidenceSealNextWait(orgclient.ErrExecSealNotSupported, prev)
		if stop {
			t.Fatal("a 404 stopped the registration")
		}
		waits = append(waits, w)
		prev = w
	}
	if waits[0] != time.Hour || waits[1] != 2*time.Hour || waits[6] != 24*time.Hour {
		t.Fatalf("404 back-off %v", waits)
	}
	// P-205: a node its org switched to enterprise asking an org server that
	// does not serve it as managed (403 managed_only, an older server) backs
	// off like a 404, so an upgraded server gets the key later.
	if w, stop := evidenceSealNextWait(orgclient.ErrExecSealNotManagedHere, 0); stop || w != time.Hour {
		t.Fatalf("a 403 managed_only: %v %v, want the 404 back-off", w, stop)
	}
	if w, stop := evidenceSealNextWait(errors.New("network down"), 0); stop || w != evidenceSealRegisterRetry {
		t.Fatalf("a network failure: %v %v", w, stop)
	}
}
