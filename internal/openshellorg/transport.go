package openshellorg

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

// transport.go is the node's relay transport per tested gateway version
// (g1-design.md section 3.3, lane G4) and the flow-control protocol every
// stdin sent through the front follows (live gate G-L2, OB-077 to OB-079).
// Pure: the wire client and the in-box wrapper hold the I/O.

// RelayShape is how the capture relay crosses the gateway.
type RelayShape string

// The closed relay shapes (design 3.3).
const (
	// RelayTTYOff: ExecSandboxInteractive with tty = false (the design's
	// primary shape; the G-L2 verdict on 0.1.6).
	RelayTTYOff RelayShape = "tty_false"
	// RelayRawTTY: the same RPC with a TTY, the guest switching its terminal
	// to raw mode before it says ready (the fallback; unused on 0.1.6).
	RelayRawTTY RelayShape = "raw_tty"
)

// TransportRow is one tested gateway version's transport facts.
type TransportRow struct {
	Version string
	Relay   RelayShape
	// Suspend: the version's Docker driver implements SuspendSandbox (a
	// held box could keep its memory). False on 0.1.6: held means stopped.
	Suspend bool
	// Grounding names the live receipt.
	Grounding string
}

// transportTable is the tested-version table, walked top-down. A version
// not listed has no transport (the probe's version verdicts refuse it).
var transportTable = []TransportRow{
	{Version: "0.1.6", Relay: RelayTTYOff, Suspend: false, Grounding: "G-L2 on lane G5 fix round 3 (OB-079): 64 MiB byte-exact four times under paced flow control; suspend answers FailedPrecondition"},
}

// TransportFor returns the transport row of a gateway version.
func TransportFor(version string) (TransportRow, bool) {
	for _, r := range transportTable {
		if r.Version == version {
			return r, true
		}
	}
	return TransportRow{}, false
}

// Flow control (OB-079). The 0.1.6 supervisor buffers an exec's stdin and
// ends the exec with exit 74 when a client outruns the box, so:
//   - an interactive stream sends stdin in frames of at most FrameBytes and
//     never more than WindowBytes ahead of the box's credit;
//   - a one-shot exec carries at most MaxOneShotStdin, and the next part is
//     sent only after the previous exec exited (its exit is the credit).
//
// MaxOneShotStdin is the largest stdin the gateway's message limit allows
// (FX4 item 2, live finding F-P6-2): the 0.1.6 gateway decodes at most
// GatewayDecodeBytes per request message (MAX_GRPC_DECODE_SIZE, 1 MiB, set
// on OpenShellServer by max_decoding_message_size in
// crates/openshell-server/src/multiplex.rs; FX3 had assumed tonic's
// implicit 4 MiB default, which that call replaces), less 64 KiB for the
// argv, environment and names. The live refusal measured the rest of the
// request at 270 bytes (found 4129038 for a stdin of 4128768), so 64 KiB is
// a margin of more than 200 times. The stdin is read by `cat` into a file,
// which drains it far faster than the 16 MiB the unpaced G-L2 probe hashed
// before the supervisor's buffer filled. At 256 KiB an in-box observer of
// 76.6 MiB took about 300 execs; at 960 KiB it takes 82 parts (84 execs
// with the tools probe and the assembly). No exec is an admitted mutation
// (FX3 item 2), so the count costs no admission.
const (
	FrameBytes      = 32 << 10
	WindowBytes     = 256 << 10
	MaxOneShotStdin = GatewayDecodeBytes - 64<<10
	// StallLimit is how long a sender waits for new credit before it gives
	// up with an error (never an unbounded wait).
	StallLimit = 120 * time.Second
)

// StreamHeartbeat is how often the node sends a heartbeat on an open
// interactive stream that has carried no other frame for that long (FX4
// item 1, live finding F-P6-3). A heartbeat is a stdin frame of zero bytes;
// the front never forwards one to the gateway (IsHeartbeat).
//
// Why: the TLS terminator in front of the front reads the node's request
// body (the stdin side of the bidirectional stream) through a per-read idle
// deadline. Caddy 2.11.5 and later do this by default
// (modules/caddyhttp/server.go, ServeHTTP's IdleTimeoutReader over
// ReadIdleTimeout, whose default defaultReadIdleTimeout in app.go is one
// minute; the Caddyfile key is read_body_idle, first in 2.11.5, which no
// shipped Caddyfile sets). An agent that sits in a tool call sends no
// keystroke for minutes, so the terminator's read of the stdin side failed
// "i/o timeout" 60 s after the node's last frame and aborted the proxied
// stream (RST_STREAM INTERNAL_ERROR to the node, a cancel to the front,
// "exec response stream closed" at the gateway). A
// one-shot exec has ended its request body by then, so it was never cut.
// Twenty seconds keeps two heartbeats inside any request-direction idle
// bound of 60 s or more (Caddy's default, nginx's client_body_timeout
// default). The heartbeat covers the request direction only: a terminator
// idle bound on the response side (nginx grpc_read_timeout, HAProxy timeout
// server) still cuts a stream whose box prints nothing for that long.
const StreamHeartbeat = 20 * time.Second

// IsHeartbeat reports whether a stdin frame is the node's heartbeat (zero
// bytes). The front drops it, so the box never sees it.
func IsHeartbeat(stdin []byte) bool { return len(stdin) == 0 }

// GatewayDecodeBytes is the 0.1.6 gateway's inbound gRPC message limit
// (MAX_GRPC_DECODE_SIZE in crates/openshell-server/src/multiplex.rs). The
// gateway fake enforces the same number (gwfake.UpstreamLimits; a test pins
// them equal).
const GatewayDecodeBytes = 1_048_576

// ExitStdinFull is the exit code the 0.1.6 supervisor gives an exec whose
// stdin buffer overflowed.
const ExitStdinFull = 74

// The credit line the in-box paced-stdin wrapper writes on its stderr after
// every chunk it hands to its child: a record separator, the tag, the
// decimal count of bytes consumed so far, a newline. Stderr carries it so
// the child's stdout (the relay's frames) stays byte-exact.
const ackTag = "\x1esbo-ack "

// AckLine is the credit line for a consumed byte count.
func AckLine(consumed int64) []byte {
	return []byte(ackTag + strconv.FormatInt(consumed, 10) + "\n")
}

// AckFilter splits a stderr stream into credit lines (reported to onAck) and
// everything else (returned for the caller's own stderr sink). It keeps a
// partial line between calls. The zero value is not usable; use
// NewAckFilter.
type AckFilter struct {
	onAck func(int64)
	buf   []byte
}

// NewAckFilter returns a filter that reports each credit line to onAck.
func NewAckFilter(onAck func(int64)) *AckFilter { return &AckFilter{onAck: onAck} }

// Feed takes the next stderr bytes and returns the bytes that are not
// credit lines. A line that is not a credit line passes through unchanged.
func (f *AckFilter) Feed(p []byte) []byte {
	f.buf = append(f.buf, p...)
	var out []byte
	for {
		i := bytes.IndexByte(f.buf, '\n')
		if i < 0 {
			break
		}
		line := f.buf[:i+1]
		if n, ok := parseAck(line); ok {
			f.onAck(n)
		} else {
			out = append(out, line...)
		}
		f.buf = f.buf[i+1:]
	}
	// A long run with no newline that cannot be a credit line passes on.
	if len(f.buf) > 0 && (f.buf[0] != ackTag[0] || len(f.buf) > len(ackTag)+20) {
		out = append(out, f.buf...)
		f.buf = nil
	}
	return out
}

func parseAck(line []byte) (int64, bool) {
	s, ok := bytes.CutPrefix(line, []byte(ackTag))
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(bytes.TrimSuffix(s, []byte("\n"))), 10, 64)
	return n, err == nil && n >= 0
}

// ErrNoCredit is a sender that saw no new credit for StallLimit.
var ErrNoCredit = errors.New("openshellorg: no flow-control credit from the box")

// Credit is the box's consumption as a sender sees it: the one owner of
// that count, shared by the receiver that reads credit lines and the sender
// that waits on them.
type Credit struct {
	mu       sync.Mutex
	consumed int64
	closed   bool
	changed  chan struct{}
}

// NewCredit returns a credit at zero.
func NewCredit() *Credit { return &Credit{changed: make(chan struct{}, 1)} }

// Set raises the consumed count (a lower or equal value changes nothing).
func (c *Credit) Set(n int64) {
	c.mu.Lock()
	if n > c.consumed {
		c.consumed = n
	}
	c.mu.Unlock()
	c.poke()
}

// Close wakes every waiter for good (the stream ended).
func (c *Credit) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.poke()
}

func (c *Credit) poke() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Consumed returns the credit.
func (c *Credit) Consumed() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consumed
}

// WaitRoom blocks until sending n more bytes after sent keeps the in-flight
// count within window: sent + n - consumed <= window. It returns
// ErrNoCredit after stall with no progress, the context's error, or
// io.ErrClosedPipe-like errClosed once the stream ended.
func (c *Credit) WaitRoom(ctx context.Context, sent, n, window int64, stall time.Duration) error {
	timer := time.NewTimer(stall)
	defer timer.Stop()
	for {
		c.mu.Lock()
		// A credit above what was sent is a box that lies (or floods credit
		// lines): it counts as everything sent, never as room beyond the
		// window (fix round 1, the 11.4 frame-flood row).
		room := sent+n-min(c.consumed, sent) <= window
		closed := c.closed
		c.mu.Unlock()
		if room {
			return nil
		}
		if closed {
			return ErrStreamEnded
		}
		select {
		case <-c.changed:
		case <-timer.C:
			return ErrNoCredit
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ErrStreamEnded is a send after the stream ended.
var ErrStreamEnded = errors.New("openshellorg: the exec stream ended")
