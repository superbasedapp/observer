package store

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/rand/v2"
	"testing"
)

// sealedGuardRow is base hashed under prev with action id anchor, then
// cleared the way maintenance cleared it before migration 197: no
// action_id, no action_anchor, the stored hash still the one anchor made.
func sealedGuardRow(base GuardEventRow, prev string, anchor int64) GuardEventRow {
	r := base
	if r.tsStored == "" {
		r.tsStored = "2026-05-17T09:27:35.175Z"
	}
	r.ChainPrev = prev
	r.ActionID = nil
	r.actionAnchor = &anchor
	r.ChainHash = guardChainHash(prev, r.canonicalBytes())
	r.actionAnchor = nil
	return r
}

// guardAnchorShapes are row shapes the split must handle: both chain
// versions, the genesis link, an api turn id beside the slot, digits and
// separators in the free text.
func guardAnchorShapes() map[string]GuardEventRow {
	turn := int64(42)
	v1 := guardEventFixture("f4e8cbf8-601f-4d49-81ab-a228003ac357", "R-150", t0Guard)
	v1.Tool, v1.EventKind = "copilot", "file_access"
	v1turn := v1
	v1turn.APITurnID = &turn
	v2 := guardEventFixture("s-123", "R-101", t0Guard)
	v2.ChainV, v2.GrantID = 2, 7
	odd := guardEventFixture("0", "R-1", t0Guard)
	odd.ChainV = 2
	odd.Reason = "0\x1f1\x1e2 café ☃"
	odd.TargetExcerpt = "1234567890"
	return map[string]GuardEventRow{"v1": v1, "v1 with api turn": v1turn, "v2 with grant": v2, "v2 odd text": odd}
}

// TestGuardAnchorPreimageMatchesCanonicalBytes pins the fast path to the
// proof of record: for every row shape and many ids (every digit-count
// boundary, the live node's ids, the widest int64 and random ones),
// head||decimal(id)||tail hashes exactly like guardChainHash over
// canonicalBytes with that id, and the trier accepts only the sealed id.
func TestGuardAnchorPreimageMatchesCanonicalBytes(t *testing.T) {
	t.Parallel()
	ids := []int64{0, 1, 2, 9, 10, 11, 99, 100, 101, 999, 1000, 2304743, 2304744, 15706162, math.MaxInt64 - 1, math.MaxInt64}
	for p := int64(10); p <= 1e18; p *= 10 {
		ids = append(ids, p-1, p, p+1)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		ids = append(ids, rng.Int64N(math.MaxInt64))
	}
	for name, base := range guardAnchorShapes() {
		for _, prev := range []string{"", guardChainHash("x", []byte("y"))} {
			const anchor = int64(2304743)
			r := sealedGuardRow(base, prev, anchor)
			p, why := newGuardAnchorPreimage(&r)
			if p == nil {
				t.Fatalf("%s: no preimage: %s", name, why)
			}
			if r.actionAnchor != nil {
				t.Fatalf("%s: newGuardAnchorPreimage left an anchor set", name)
			}
			tr := p.newTrier()
			for _, id := range ids {
				sum := sha256.Sum256(p.appendPreimage(nil, id))
				r.actionAnchor = &id
				want := guardChainHash(r.ChainPrev, r.canonicalBytes())
				r.actionAnchor = nil
				if got := hex.EncodeToString(sum[:]); got != want {
					t.Fatalf("%s prev %q id %d: split hash %s, canonical %s", name, prev, id, got, want)
				}
				if got := tr.try(id); got != (id == anchor) {
					t.Fatalf("%s prev %q: try(%d) = %v", name, prev, id, got)
				}
			}
		}
	}
}

// TestGuardAnchorPreimageRefuses: rows no id can prove get a reason, not a
// split.
func TestGuardAnchorPreimageRefuses(t *testing.T) {
	t.Parallel()
	base := guardEventFixture("s1", "R-150", t0Guard)
	action := int64(5)
	cases := []struct {
		name   string
		mutate func(r *GuardEventRow)
		want   string
	}{
		{"unknown chain version", func(r *GuardEventRow) { r.ChainV = 99 }, guardAnchorNoSlot},
		{"uppercase hash", func(r *GuardEventRow) { r.ChainHash = upperHex(r.ChainHash) }, guardAnchorBadHash},
		{"short hash", func(r *GuardEventRow) { r.ChainHash = r.ChainHash[:10] }, guardAnchorBadHash},
		{"not hex", func(r *GuardEventRow) { r.ChainHash = "z" + r.ChainHash[1:] }, guardAnchorBadHash},
		{"still has its action id", func(r *GuardEventRow) { r.ActionID = &action }, guardAnchorHasAction},
		{"still has its anchor", func(r *GuardEventRow) { r.actionAnchor = &action }, guardAnchorHasAction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := sealedGuardRow(base, "", 9)
			tc.mutate(&r)
			if p, why := newGuardAnchorPreimage(&r); p != nil || why != tc.want {
				t.Fatalf("newGuardAnchorPreimage = (%v, %q), want (nil, %q)", p, why, tc.want)
			}
		})
	}
}

func upperHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
