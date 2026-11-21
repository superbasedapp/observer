package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// guardAnchorPreimage is one repair candidate's chain-hash preimage split
// around its action slot, so trying an action id only encodes that integer
// and hashes: SHA-256(head || decimal(id) || tail) is the chain_hash the row
// would carry with action id id and every other column as stored, where
// head = chain_prev || 0x1e || the canonical bytes before the slot and tail
// = the canonical bytes after it. It is a fast path only: an id it accepts is
// confirmed through canonicalBytes before the repair accepts it.
type guardAnchorPreimage struct {
	head, tail []byte
	want       [sha256.Size]byte
	// key identifies the row's content: SHA-256 of its canonical bytes with
	// the action slot empty (every hashed column but chain_prev and the
	// action id). Repeats of one row share it (guardAnchorHintContent).
	key [sha256.Size]byte
}

// Reasons newGuardAnchorPreimage gives for a row no action id can prove.
const (
	guardAnchorNoSlot    = "its chain input has no action slot (unknown chain version)"
	guardAnchorBadHash   = "its stored chain_hash is not a SHA-256 hex digest"
	guardAnchorHasAction = "it already carries an action id"
)

// guardAnchorSplitProbes are the ids newGuardAnchorPreimage checks its split
// against canonicalBytes with: one digit, a digit-count boundary and the
// widest int64, so a split that only works for one width is refused.
var guardAnchorSplitProbes = []int64{0, 7, 9, 10, 99999, 100000, 2304743, 9223372036854775807}

// newGuardAnchorPreimage splits r's preimage around its action slot. It
// returns "" and the split, or a reason no id can prove r (a row with no
// slot, a malformed stored hash) and nil. r must carry neither action_id nor
// action_anchor; r is left as it was.
func newGuardAnchorPreimage(r *GuardEventRow) (*guardAnchorPreimage, string) {
	if r.ActionID != nil || r.actionAnchor != nil {
		return nil, guardAnchorHasAction
	}
	want, err := hex.DecodeString(r.ChainHash)
	// guardChainHash writes lowercase hex; anything else can never match.
	if err != nil || len(want) != sha256.Size || hex.EncodeToString(want) != r.ChainHash {
		return nil, guardAnchorBadHash
	}
	defer func() { r.actionAnchor = nil }()
	empty := r.canonicalBytes() // the slot renders as "" while no id is set
	zero := int64(0)
	r.actionAnchor = &zero
	withZero := r.canonicalBytes()
	if len(withZero) != len(empty)+1 {
		return nil, guardAnchorNoSlot
	}
	// The slot is where the two serializations first differ.
	k := 0
	for k < len(empty) && empty[k] == withZero[k] {
		k++
	}
	p := &guardAnchorPreimage{
		head: append(append([]byte(r.ChainPrev), 0x1e), empty[:k]...),
		tail: append([]byte(nil), empty[k:]...),
		key:  sha256.Sum256(empty),
	}
	copy(p.want[:], want)
	prefix := len(r.ChainPrev) + 1
	for _, id := range guardAnchorSplitProbes {
		r.actionAnchor = &id
		if !bytes.Equal(p.appendPreimage(nil, id)[prefix:], r.canonicalBytes()) {
			return nil, guardAnchorNoSlot
		}
	}
	return p, ""
}

// appendPreimage appends the preimage with action id id to buf.
func (p *guardAnchorPreimage) appendPreimage(buf []byte, id int64) []byte {
	buf = append(buf, p.head...)
	buf = strconv.AppendInt(buf, id, 10)
	return append(buf, p.tail...)
}

// guardAnchorTrier tests action ids against one preimage. Not safe for
// concurrent use: each search worker owns one (they share the preimage).
type guardAnchorTrier struct {
	p   *guardAnchorPreimage
	buf []byte
}

// newTrier returns a trier with its own scratch buffer.
func (p *guardAnchorPreimage) newTrier() *guardAnchorTrier {
	return &guardAnchorTrier{p: p, buf: make([]byte, 0, len(p.head)+20+len(p.tail))}
}

// try reports whether id reproduces the stored chain_hash.
func (t *guardAnchorTrier) try(id int64) bool {
	t.buf = t.p.appendPreimage(t.buf[:0], id)
	return sha256.Sum256(t.buf) == t.p.want
}
