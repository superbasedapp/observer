package sandboxrelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// The hostile guest suite (sandbox plan section 13.12, A5; JSP-3's 29
// scenarios). Since lane sbx-p2 every scenario runs behind a PROCESS
// boundary: the test binary re-executes itself as the hostile guest
// (TestHostileGuestProcess, selected by SBR_HOSTILE_SCENARIO), which dials
// a real unix socket the host-side Reader verifies. The host must close
// with the expected error, within the bound, without growing memory.

var testSecret = []byte("0123456789abcdef0123456789abcdef") // test-only per-run secret

var testNonce = make([]byte, NonceSize)

// testLimits keep JSP-3's 256 KiB window so the overrun row is cheap.
var testLimits = Limits{MaxPayload: 64 << 10, MaxStreams: 16, InitialWindow: 256 << 10, MaxWindow: 1 << 20}

func testKeys(t testing.TB, runID string, epoch uint32) Keys {
	k, err := DeriveKeys(testSecret, PurposeBox, runID, testNonce, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type scenario struct {
	name    string
	lim     ConnLimits
	guest   func(c net.Conn, k Keys)
	wantErr error
	timeout bool
	okFrame int
	within  time.Duration
}

func fastLimits() ConnLimits {
	l := DefaultConnLimits
	l.FrameDeadline = 200 * time.Millisecond
	l.IdleTimeout = 400 * time.Millisecond
	return l
}

func seal(k []byte, t byte, stream uint32, seq uint64, epoch uint32, p []byte) []byte {
	return SealRaw(nil, hmac.New(sha256.New, k), t, stream, seq, epoch, p)
}

func write(c net.Conn, b []byte) { _, _ = c.Write(b) }

func scenarios(t testing.TB) []scenario {
	fl := fastLimits()
	data := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	return []scenario{
		{
			name: "control: three valid frames then clean close", lim: fl, okFrame: 3, wantErr: io.EOF, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				s := NewSealer(k.GuestToHost, k.Epoch)
				for i := 0; i < 3; i++ {
					write(c, s.Seal(nil, TypeData, 1, data))
				}
			},
		},
		{
			name: "oversized frame (length 4 GiB)", lim: fl, wantErr: ErrTooLarge, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				h := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, nil)
				binary.BigEndian.PutUint32(h[16:20], 0xFFFFFFFF)
				write(c, h[:HeaderSize])
			},
		},
		{
			name: "oversized frame (cap + 1)", lim: fl, wantErr: ErrTooLarge, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, make([]byte, testLimits.MaxPayload+1)))
			},
		},
		{
			name: "truncated header then close", lim: fl, wantErr: io.ErrUnexpectedEOF, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)[:10]) },
		},
		{
			name: "truncated payload then close", lim: fl, wantErr: io.ErrUnexpectedEOF, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)[:HeaderSize+5]) },
		},
		{
			name: "truncated frame then stall", lim: fl, timeout: true, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)[:HeaderSize+5])
				time.Sleep(2 * time.Second)
			},
		},
		{
			name: "replay of frame 1", lim: fl, okFrame: 1, wantErr: ErrSeq, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				write(c, f)
				write(c, f)
			},
		},
		{
			name: "skipped sequence (1 then 3)", lim: fl, okFrame: 1, wantErr: ErrSeq, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data))
				write(c, seal(k.GuestToHost, TypeData, 1, 3, k.Epoch, data))
			},
		},
		{
			name: "out of order (2 first)", lim: fl, wantErr: ErrSeq, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				write(c, seal(k.GuestToHost, TypeData, 1, 2, k.Epoch, data))
				write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data))
			},
		},
		{
			name: "bad MAC: payload bit flip", lim: fl, wantErr: ErrMAC, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				f[HeaderSize+3] ^= 1
				write(c, f)
			},
		},
		{
			name: "bad MAC: stream id changed", lim: fl, wantErr: ErrMAC, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				f[7] = 2
				write(c, f)
			},
		},
		{
			name: "bad MAC: truncated tag", lim: fl, timeout: true, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				write(c, f[:len(f)-1])
				time.Sleep(2 * time.Second)
			},
		},
		{
			name: "reflection: host-to-guest frame echoed back", lim: fl, wantErr: ErrMAC, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.HostToGuest, TypeData, 1, 1, k.Epoch, data)) },
		},
		{
			name: "wrong per-run secret", lim: fl, wantErr: ErrMAC, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				other, _ := DeriveKeys([]byte("ffffffffffffffffffffffffffffffff"), PurposeBox, "run-1", testNonce, k.Epoch)
				write(c, seal(other.GuestToHost, TypeData, 1, 1, k.Epoch, data))
			},
		},
		{
			name: "other run's key (run id bound)", lim: fl, wantErr: ErrMAC, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				other, _ := DeriveKeys(testSecret, PurposeBox, "run-2", testNonce, k.Epoch)
				write(c, seal(other.GuestToHost, TypeData, 1, 1, k.Epoch, data))
			},
		},
		{
			name: "stale epoch after re-key", lim: fl, wantErr: ErrEpoch, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeData, 1, 1, k.Epoch-1, data)) },
		},
		{
			name: "unknown stream", lim: fl, wantErr: ErrStream, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeData, 99, 1, k.Epoch, data)) },
		},
		{
			name: "guest opens a stream", lim: fl, wantErr: ErrDirection, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeOpen, 7, 1, k.Epoch, nil)) },
		},
		{
			name: "guest sends re-key", lim: fl, wantErr: ErrDirection, within: time.Second,
			guest: func(c net.Conn, k Keys) { write(c, seal(k.GuestToHost, TypeRekey, 0, 1, k.Epoch, nil)) },
		},
		{
			name: "data after close", lim: fl, okFrame: 1, wantErr: ErrStream, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				s := NewSealer(k.GuestToHost, k.Epoch)
				write(c, s.Seal(nil, TypeClose, 1, nil))
				write(c, s.Seal(nil, TypeData, 1, data))
			},
		},
		{
			name: "window overrun (no credit)", lim: fl, okFrame: 4, wantErr: ErrWindow, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				s := NewSealer(k.GuestToHost, k.Epoch)
				big := make([]byte, testLimits.MaxPayload)
				for i := 0; i < 5; i++ { // 5 x 64 KiB > the 256 KiB window
					write(c, s.Seal(nil, TypeData, 1, big))
				}
			},
		},
		{
			name: "bad magic", lim: fl, wantErr: ErrMagic, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				f[0] = 0
				write(c, f)
			},
		},
		{
			name: "nonzero flags", lim: fl, wantErr: ErrFlags, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				f[3] = 1
				write(c, f)
			},
		},
		{
			name: "unknown type", lim: fl, wantErr: ErrType, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				f[2] = 0x7F
				write(c, f)
			},
		},
		{
			name: "random garbage", lim: fl, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				b := make([]byte, 4096)
				rand.New(rand.NewSource(1)).Read(b) //nolint:gosec // G404: deterministic test garbage
				write(c, b)
			},
		},
		{
			name: "slow drip (1 byte per 20 ms, valid frame)", lim: fl, timeout: true, within: time.Second,
			guest: func(c net.Conn, k Keys) {
				f := seal(k.GuestToHost, TypeData, 1, 1, k.Epoch, data)
				for _, b := range f {
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			},
		},
		{
			name: "silent guest (idle)", lim: fl, timeout: true, within: time.Second,
			guest: func(net.Conn, Keys) { time.Sleep(2 * time.Second) },
		},
		{
			name: "flood: max-size frames, no pause", lim: DefaultConnLimits, wantErr: ErrRate, within: 5 * time.Second,
			guest: func(c net.Conn, k Keys) { flood(c, k, int(testLimits.MaxPayload)) },
		},
		{
			name: "flood: empty ping frames", lim: DefaultConnLimits, wantErr: ErrRate, within: 5 * time.Second,
			guest: func(c net.Conn, k Keys) { flood(c, k, -1) },
		},
	}
}

// flood sends valid frames as fast as the socket takes them.
func flood(c net.Conn, k Keys, size int) {
	s := NewSealer(k.GuestToHost, k.Epoch)
	var p []byte
	t, stream := TypePing, uint32(0)
	if size >= 0 {
		p, t, stream = make([]byte, size), TypeData, 1
	}
	buf := []byte{}
	for {
		buf = s.Seal(buf[:0], t, stream, p)
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

// TestHostileGuestProcess is the guest half: it runs only when the suite
// re-executes the test binary with SBR_HOSTILE_SCENARIO set.
func TestHostileGuestProcess(t *testing.T) {
	idx := os.Getenv("SBR_HOSTILE_SCENARIO")
	if idx == "" {
		t.Skip("the hostile guest process half (run by TestHostileGuest)")
	}
	i, err := strconv.Atoi(idx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", os.Getenv("SBR_HOSTILE_SOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	scenarios(t)[i].guest(c, testKeys(t, "run-1", 3))
}

type outcome struct {
	err        error
	ok         int
	elapsed    time.Duration
	heapGrowth int64
}

func runScenario(t *testing.T, i int, sc scenario) outcome {
	sock := filepath.Join(t.TempDir(), "relay.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	guest := exec.Command(os.Args[0], "-test.run=^TestHostileGuestProcess$", "-test.count=1") //nolint:gosec // G204: the test binary re-executing itself
	guest.Env = append(os.Environ(), "SBR_HOSTILE_SCENARIO="+strconv.Itoa(i), "SBR_HOSTILE_SOCK="+sock)
	if err := guest.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = guest.Process.Kill(); _ = guest.Wait() }()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	keys := testKeys(t, "run-1", 3)
	o := NewOpener(HostSide, keys.GuestToHost, keys.Epoch, testLimits)
	if err := o.Grant(1); err != nil {
		t.Fatal(err)
	}
	// In the flood rows the host keeps re-granting credit, as a live
	// consumer would; the rate limiter, not the window, must stop it.
	refill := errors.Is(sc.wantErr, ErrRate)
	r := NewReader(c, o, sc.lim, nil)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	var res outcome
	for {
		h, _, err := r.Next()
		if err != nil {
			res.err = err
			break
		}
		res.ok++
		if refill && h.Type == TypeData {
			o.streams[1].credit = testLimits.InitialWindow
		}
	}
	res.elapsed = time.Since(start)
	runtime.ReadMemStats(&m1)
	res.heapGrowth = int64(m1.HeapAlloc) - int64(m0.HeapAlloc) //nolint:gosec // G115: heap sizes fit int64
	return res
}

// TestHostileGuest runs every scenario against a guest in its own process.
func TestHostileGuest(t *testing.T) {
	if os.Getenv("SBR_HOSTILE_SCENARIO") != "" {
		t.Skip("inside the guest process")
	}
	all := scenarios(t)
	if len(all) != 29 {
		t.Fatalf("%d scenarios, JSP-3 has 29", len(all))
	}
	for i, sc := range all {
		t.Run(sc.name, func(t *testing.T) {
			res := runScenario(t, i, sc)
			var ne net.Error
			isTimeout := errors.As(res.err, &ne) && ne.Timeout()
			switch {
			case sc.timeout && !isTimeout:
				t.Errorf("want a deadline error, got %v", res.err)
			case !sc.timeout && sc.wantErr != nil && !errors.Is(res.err, sc.wantErr):
				t.Errorf("want %v, got %v", sc.wantErr, res.err)
			case !sc.timeout && sc.wantErr == nil && (res.err == nil || isTimeout):
				t.Errorf("want a protocol error, got %v", res.err)
			}
			if sc.okFrame > 0 && res.ok != sc.okFrame && !errors.Is(sc.wantErr, ErrRate) {
				t.Errorf("want %d good frames before the failure, got %d", sc.okFrame, res.ok)
			}
			if res.elapsed > sc.within {
				t.Errorf("closed after %v, want within %v", res.elapsed, sc.within)
			}
			if res.heapGrowth > 1<<20 {
				t.Errorf("heap grew %d bytes", res.heapGrowth)
			}
			t.Log(fmt.Sprintf("closed with %v after %d frames in %v", res.err, res.ok, res.elapsed.Round(time.Millisecond)))
		})
	}
}

// TestReKey: the host announces epoch+1, the guest switches, the sequence
// restarts at 1, and an old-epoch frame is refused.
func TestReKey(t *testing.T) {
	k0, k1 := testKeys(t, "run-1", 0), testKeys(t, "run-1", 1)
	o := NewOpener(HostSide, k0.GuestToHost, 0, testLimits)
	if err := o.Grant(1); err != nil {
		t.Fatal(err)
	}
	s := NewSealer(k0.GuestToHost, 0)
	for i := 0; i < 3; i++ {
		if _, _, err := o.Open(s.Seal(nil, TypeData, 1, []byte("x"))); err != nil {
			t.Fatal(err)
		}
	}
	o.Rekey(k1.GuestToHost, 1)
	old := s.Seal(nil, TypeData, 1, []byte("old"))
	s.Rekey(k1.GuestToHost, 1)
	if _, _, err := o.Open(s.Seal(nil, TypeData, 1, []byte("new"))); err != nil {
		t.Fatalf("first frame of the new epoch: %v", err)
	}
	if _, _, err := o.Open(old); !errors.Is(err, ErrEpoch) {
		t.Fatalf("old-epoch frame: want ErrEpoch, got %v", err)
	}
}

func BenchmarkSealOpen(b *testing.B) {
	for _, n := range []int{256, 1 << 10, 16 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			k := testKeys(b, "run-1", 0)
			lim := testLimits
			lim.InitialWindow, lim.MaxWindow = 1<<31, 1<<31
			o := NewOpener(HostSide, k.GuestToHost, 0, lim)
			_ = o.Grant(1)
			s := NewSealer(k.GuestToHost, 0)
			p := make([]byte, n)
			buf := []byte{}
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf = s.Seal(buf[:0], TypeData, 1, p)
				if _, _, err := o.Open(buf); err != nil {
					b.Fatal(err)
				}
				o.streams[1].credit = lim.InitialWindow
			}
		})
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKeys(testSecret, PurposeBox, "run-1", testNonce, uint32(i)); err != nil { //nolint:gosec // G115: a benchmark counter
			b.Fatal(err)
		}
	}
}
