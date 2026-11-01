package sandboxrelay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"testing"
	"time"
)

// The two fuzz targets of sandbox plan section 13.12 (A5), as JSP-3 asked:
// raw bytes through the full reader, and sealed operations checked against
// a reference model (without the second the fuzzer never gets past the
// MAC). The seed corpus under testdata/fuzz is the JSP-3 corpus.

// fakeConn reads from a byte slice; deadlines are recorded, never fired,
// so fuzzing stays deterministic.
type fakeConn struct{ r *bytes.Reader }

func (f *fakeConn) Read(p []byte) (int, error)      { return f.r.Read(p) }
func (f *fakeConn) SetReadDeadline(time.Time) error { return nil }

func fuzzLimits() Limits {
	return Limits{MaxPayload: 4096, MaxStreams: 4, InitialWindow: 8192, MaxWindow: 16384}
}

// FuzzReaderRaw feeds raw bytes, exactly as a hostile guest could write
// them, through the full Reader (header, length cap, MAC, sequence, state
// machine, rate limiter on a fake clock). Properties: the error is sticky,
// accepted lengths are within the cap, accepted sequences are 1, 2, 3...
func FuzzReaderRaw(f *testing.F) {
	k := testKeys(f, "run-1", 0)
	s := NewSealer(k.GuestToHost, 0)
	var seed []byte
	seed = s.Seal(seed, TypeData, 1, []byte(`{"hook_event_name":"PreToolUse"}`))
	seed = s.Seal(seed, TypePing, 0, nil)
	seed = s.Seal(seed, TypeClose, 1, nil)
	f.Add(seed)
	f.Add(seed[:HeaderSize])
	f.Add([]byte{})
	big := make([]byte, HeaderSize)
	copy(big, seed[:HeaderSize])
	binary.BigEndian.PutUint32(big[16:20], 0xFFFFFFFF)
	f.Add(big)
	f.Fuzz(func(t *testing.T, data []byte) {
		lim := fuzzLimits()
		o := NewOpener(HostSide, k.GuestToHost, 0, lim)
		_ = o.Grant(1)
		_ = o.Grant(2)
		clock := time.Unix(0, 0)
		r := NewReader(&fakeConn{bytes.NewReader(data)}, o, DefaultConnLimits, func() time.Time {
			clock = clock.Add(time.Millisecond)
			return clock
		})
		for i := 0; ; i++ {
			h, p, err := r.Next()
			if err != nil {
				if _, _, err2 := r.Next(); !errors.Is(err2, err) {
					t.Fatalf("error not sticky: %v then %v", err, err2)
				}
				return
			}
			if int(h.Len) != len(p) || h.Len > lim.MaxPayload {
				t.Fatalf("length mismatch %d %d", h.Len, len(p))
			}
			if h.Seq != uint64(i+1) { //nolint:gosec // G115: a loop counter
				t.Fatalf("accepted seq %d at frame %d", h.Seq, i)
			}
		}
	})
}

// FuzzOpenerSealed treats the input as a script of frame operations
// sealed with the RIGHT key, so the fuzzer gets past the MAC and explores
// the sequence, epoch, stream, window and direction rules, against a
// reference model kept beside the opener.
func FuzzOpenerSealed(f *testing.F) {
	f.Add([]byte{0, 2, 1, 0, 0, 10, 0, 3, 1, 0, 0, 0})
	f.Add([]byte{1, 1, 5, 0, 0, 0, 1, 2, 5, 0, 0, 4})
	f.Add([]byte{0, 2, 1, 1, 0, 0, 0, 2, 1, 0, 1, 0, 0, 6, 0, 0, 0, 0})
	k := testKeys(f, "run-1", 0)
	k1 := testKeys(f, "run-1", 1)
	f.Fuzz(func(t *testing.T, script []byte) {
		role := HostSide
		if len(script) > 0 && script[0]&1 == 1 {
			role = GuestSide
		}
		lim := fuzzLimits()
		o := NewOpener(role, k.GuestToHost, 0, lim)
		granted := map[uint32]bool{}
		if role == HostSide {
			_ = o.Grant(1)
			granted[1] = true
		}
		closed := map[uint32]bool{}
		sent := map[uint32]uint32{}
		seq, epoch := uint64(0), uint32(0)
		armed := false
		in := script
		if len(in) > 0 {
			in = in[1:]
		}
		for len(in) >= 6 {
			op := in[:6]
			in = in[6:]
			typ := op[0]%7 + 1 // includes the invalid type 7
			stream := uint32(op[1] % 4)
			seqDelta := int64(int8(op[2]))
			epochSel := op[3] % 3
			n := int(binary.BigEndian.Uint16(op[4:6])) % (int(lim.MaxPayload) + 2)
			if epochSel == 2 && !armed {
				o.Rekey(k1.GuestToHost, 1)
				armed = true
			}
			fe, key := uint32(0), k.GuestToHost
			if epochSel >= 1 {
				fe, key = 1, k1.GuestToHost
			}
			nextSeq := seq + 1
			if fe != epoch {
				nextSeq = 1
			}
			fseq := uint64(int64(nextSeq) + seqDelta - 1) //nolint:gosec // G115: a fuzzed delta
			if seqDelta == 0 {
				fseq = nextSeq
			}
			payload := make([]byte, n)
			if n > len(in) {
				copy(payload, in)
			} else {
				copy(payload, in[:n])
			}
			h, _, err := o.Open(SealRaw(nil, newMAC(key), typ, stream, fseq, fe, payload))
			if err != nil {
				return // every error is fatal by design; the model stops too
			}
			if fe != epoch {
				if !armed || fe != 1 {
					t.Fatalf("accepted unarmed epoch %d", fe)
				}
				epoch, seq, armed = fe, 0, false
			}
			if h.Seq != seq+1 {
				t.Fatalf("accepted seq %d, want %d", h.Seq, seq+1)
			}
			seq = h.Seq
			if typ > TypeRekey {
				t.Fatalf("accepted unknown type %d", typ)
			}
			if role == HostSide && (typ == TypeOpen || typ == TypeRekey) {
				t.Fatalf("host accepted guest %d", typ)
			}
			switch typ {
			case TypeOpen:
				if granted[stream] || stream == 0 || n != 0 {
					t.Fatalf("bad open accepted on %d (granted %v, %d bytes)", stream, granted[stream], n)
				}
				granted[stream] = true
			case TypeData:
				if !granted[stream] || closed[stream] {
					t.Fatalf("data on stream %d granted=%v closed=%v", stream, granted[stream], closed[stream])
				}
				sent[stream] += uint32(n) //nolint:gosec // G115: n is bounded by MaxPayload
				if sent[stream] > lim.InitialWindow {
					t.Fatalf("window: %d bytes on stream %d without credit", sent[stream], stream)
				}
			case TypeClose:
				if !granted[stream] || closed[stream] || n != 0 {
					t.Fatalf("bad close accepted on %d", stream)
				}
				closed[stream] = true
			}
		}
	})
}

func newMAC(key []byte) hash.Hash { return hmac.New(sha256.New, key) }

// TestFuzzSeedsPass keeps the seeds meaningful: a valid raw seed decodes.
func TestFuzzSeedsPass(t *testing.T) {
	k := testKeys(t, "run-1", 0)
	s := NewSealer(k.GuestToHost, 0)
	var seed []byte
	seed = s.Seal(seed, TypeData, 1, []byte("x"))
	seed = s.Seal(seed, TypePing, 0, nil)
	o := NewOpener(HostSide, k.GuestToHost, 0, fuzzLimits())
	_ = o.Grant(1)
	r := NewReader(&fakeConn{bytes.NewReader(seed)}, o, DefaultConnLimits, nil)
	for i := 0; i < 2; i++ {
		if _, _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}
