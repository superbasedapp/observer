package sandboxrelay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzForwardRekey is the third fuzz target of sandbox plan section 13.12
// (A5; plans decision log P-032, lane sbx-p2c): a script of guest frames,
// sealed with the right keys so the fuzzer gets past the MAC, driven
// through the host's cut-through Session.Forward with re-keying every few
// dozen bytes, so the guest's epoch changes race the host's announcements.
// Properties: Forward never panics; a message it returns passes the Whole
// check; what reached the next hop, read back under the link key, is
// exactly that message; and when Forward fails, the next hop never holds a
// whole message (it never receives a message that failed a check).
//
// Script operations (one op byte, then its operands):
//
//	0 n:u16 bytes[n]  a Data frame on the hook stream
//	1                 a Ping
//	2                 the guest follows to the next key epoch
//	3                 a Close of the hook stream
//	4 n:u16 bytes[n]  a Data frame on another stream
//	5                 a Rekey frame announcing the next epoch (a guest may not)
func FuzzForwardRekey(f *testing.F) {
	for _, seed := range forwardSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script []byte) {
		_ = fuzzForward(t, script)
	})
}

// TestForwardRekeySeeds: the valid seeds really forward (one frame, and
// split across frames with a ping and a guest epoch change between them),
// so the target explores past the happy path rather than failing early.
func TestForwardRekeySeeds(t *testing.T) {
	seeds := forwardSeeds()
	for i, want := range []bool{true, true, false, false, false} {
		if err := fuzzForward(t, seeds[i]); (err == nil) != want {
			t.Errorf("seed %d: forward error %v, want success %v", i, err, want)
		}
	}
}

// forwardRules accept one declarable variable, as the relay's do.
var forwardRules = RequestRules{EnvAllowed: func(n string) bool { return n == "OBSERVER_SANDBOX" }}

func fuzzForward(t *testing.T, script []byte) error {
	lim := fuzzLimits()
	guestKeys := func(epoch uint32) Keys { return testKeys(t, "run-1", epoch) }
	// The guest's frames, sealed as the script says.
	gs := NewSealer(guestKeys(0).GuestToHost, 0)
	gEpoch := uint32(0)
	var wire []byte
	for in := script; len(in) > 0; {
		op := in[0] % 6
		in = in[1:]
		switch op {
		case 0, 4:
			if len(in) < 2 {
				in = nil
				continue
			}
			n := int(binary.BigEndian.Uint16(in[:2])) % (int(lim.MaxPayload) + 1)
			in = in[2:]
			n = min(n, len(in))
			stream := StreamHook
			if op == 4 {
				stream = 2
			}
			wire = gs.Seal(wire, TypeData, stream, in[:n])
			in = in[n:]
		case 1:
			wire = gs.Seal(wire, TypePing, 0, nil)
		case 2:
			gEpoch++
			gs.Rekey(guestKeys(gEpoch).GuestToHost, gEpoch)
		case 3:
			wire = gs.Seal(wire, TypeClose, StreamHook, nil)
		case 5:
			var ann [4]byte
			binary.BigEndian.PutUint32(ann[:], gEpoch+1)
			wire = gs.Seal(wire, TypeRekey, 0, ann[:])
		}
	}
	clock := time.Unix(0, 0)
	now := func() time.Time {
		clock = clock.Add(time.Microsecond)
		return clock
	}
	k0 := guestKeys(0)
	o := NewOpener(HostSide, k0.GuestToHost, 0, lim)
	_ = o.Grant(StreamHook)
	conn := DefaultConnLimits
	conn.MessageDeadline = 0
	host := &Session{
		RunID:  "run-1",
		r:      NewReader(&fakeConn{bytes.NewReader(wire)}, o, conn, now),
		w:      NewWriter(&bufConn{}, NewSealer(k0.HostToGuest, 0), 0, now),
		p:      Params{Purpose: PurposeBox, Limits: lim, Conn: conn, Now: now, RekeyAfter: 48},
		secret: testSecret, nonce: testNonce, host: true,
	}
	// The next hop: a link session whose frames land in a buffer.
	linkKeys, err := DeriveKeys(testSecret, PurposeLink, "run-1", testNonce, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hop bufConn
	next := &Session{
		RunID: "run-1",
		w:     NewWriter(&hop, NewSealer(linkKeys.GuestToHost, 0), 0, now),
		p:     Params{Purpose: PurposeLink, Limits: lim, Conn: conn, Now: now},
	}
	opened := false
	checks := ForwardChecks{
		Head: func(sofar []byte) (bool, error) { return CheckHookRequestHead(sofar, forwardRules) },
		Whole: func(msg []byte) error {
			_, err := DecodeHookRequest(msg, forwardRules)
			return err
		},
	}
	dst, msg, ferr := host.Forward(StreamHook, 1<<16, checks, func() (*Session, error) {
		opened = true
		return next, nil
	})
	if dst != nil && !opened {
		t.Fatal("a next hop came back that was never opened")
	}
	// Read back what reached the next hop under the link key.
	lo := NewOpener(HostSide, linkKeys.GuestToHost, 0, lim)
	_ = lo.Grant(StreamHook)
	lr := NewReader(&fakeConn{bytes.NewReader(hop.Bytes())}, lo, DefaultConnLimits, now)
	a := NewAssembler(1 << 16)
	var whole []byte
	for {
		h, p, err := lr.Next()
		if err != nil {
			break
		}
		if h.Type != TypeData || h.Stream != StreamHook {
			t.Fatalf("the next hop got a frame of type %d on stream %d", h.Type, h.Stream)
		}
		m, err := a.Add(p)
		if err != nil {
			t.Fatalf("the next hop's message does not assemble: %v", err)
		}
		if m != nil {
			whole = m
			break
		}
	}
	if ferr != nil {
		if whole != nil {
			t.Fatalf("Forward failed (%v) but the next hop holds a whole message", ferr)
		}
		return ferr
	}
	if _, err := DecodeHookRequest(msg, forwardRules); err != nil {
		t.Fatalf("Forward returned a message that fails the whole check: %v", err)
	}
	if !bytes.Equal(whole, msg) {
		t.Fatalf("the next hop got %d bytes, Forward returned %d", len(whole), len(msg))
	}
	return nil
}

// bufConn is a write end that keeps every byte (deadlines ignored).
type bufConn struct{ bytes.Buffer }

func (*bufConn) SetWriteDeadline(time.Time) error { return nil }

// forwardSeeds are valid scripts (a hook request in one frame, split
// across frames with pings and an epoch change between them), plus every
// entry of the JSP-3 corpus the other two targets carry, as raw scripts.
func forwardSeeds() [][]byte {
	msg, err := EncodeHookRequest(HookRequest{Args: []string{"claude-code", "PreToolUse"}, Env: map[string]string{"OBSERVER_SANDBOX": "1"}, Cwd: "/w", Stdin: bytes.Repeat([]byte("p"), 300)})
	if err != nil {
		panic(err)
	}
	framed := binary.BigEndian.AppendUint32(nil, uint32(len(msg))) //nolint:gosec // G115: a short test message
	framed = append(framed, msg...)
	data := func(b []byte) []byte {
		out := []byte{0}
		out = binary.BigEndian.AppendUint16(out, uint16(len(b))) //nolint:gosec // G115: a short chunk
		return append(out, b...)
	}
	var split []byte
	split = append(split, data(framed[:40])...)
	split = append(split, 1)
	split = append(split, data(framed[40:100])...)
	split = append(split, 2)
	split = append(split, data(framed[100:])...)
	seeds := [][]byte{data(framed), split, append(data(framed[:20]), 3), append(data(framed[:20]), 5), append(data(framed[:20]), data(framed[:4])...)}
	for _, target := range []string{"FuzzReaderRaw", "FuzzOpenerSealed"} {
		dir := filepath.Join("testdata", "fuzz", target)
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if b, ok := readCorpusEntry(filepath.Join(dir, e.Name())); ok {
				seeds = append(seeds, b)
			}
		}
	}
	return seeds
}

// readCorpusEntry reads the one []byte value of a "go test fuzz v1" file.
func readCorpusEntry(path string) ([]byte, bool) {
	fh, err := os.Open(path) //nolint:gosec // G304: the package's own corpus
	if err != nil {
		return nil, false
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "[]byte(") || !strings.HasSuffix(line, ")") {
			continue
		}
		s, err := strconv.Unquote(line[len("[]byte(") : len(line)-1])
		if err != nil {
			return nil, false
		}
		return []byte(s), true
	}
	return nil, false
}
