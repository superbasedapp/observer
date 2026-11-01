package sandboxrelay

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The message layer of a stream (JSP-3): a message larger than one frame
// is chunked across Data frames behind a 4-byte big-endian length prefix,
// with a per-message cap checked before anything is buffered.

// MaxMessage caps one message on the hook stream: the hook command's own
// 8 MiB prompt limit plus room for the request header.
const MaxMessage = 8<<20 + 64<<10

// messagePrefix is the length prefix size.
const messagePrefix = 4

// ErrMessage reports a malformed or oversized message.
var ErrMessage = errors.New("sandboxrelay: malformed or oversized message")

// AppendMessageFrames splits msg into frame payloads of at most maxPayload
// bytes, the first carrying the length prefix, and calls emit for each.
func AppendMessageFrames(msg []byte, maxPayload uint32, emit func(chunk []byte) error) error {
	var first []byte
	return messageParts(msg, maxPayload, func(prefix, chunk []byte) error {
		if prefix == nil {
			return emit(chunk)
		}
		first = append(append(first[:0], prefix...), chunk...)
		return emit(first)
	})
}

// messageParts is AppendMessageFrames without joining the first chunk to
// its length prefix: emit gets the prefix (nil after the first frame) and
// the chunk, so a sealer can write both without a copy.
func messageParts(msg []byte, maxPayload uint32, emit func(prefix, chunk []byte) error) error {
	if len(msg) > MaxMessage {
		return fmt.Errorf("%w: %d bytes over the %d cap", ErrMessage, len(msg), MaxMessage)
	}
	if maxPayload <= messagePrefix {
		return fmt.Errorf("%w: frame cap too small", ErrMessage)
	}
	var prefix [messagePrefix]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(msg))) //nolint:gosec // G115: bounded by MaxMessage above
	n := min(len(msg), int(maxPayload)-messagePrefix)
	if err := emit(prefix[:], msg[:n]); err != nil {
		return err
	}
	for rest := msg[n:]; len(rest) > 0; {
		k := min(len(rest), int(maxPayload))
		if err := emit(nil, rest[:k]); err != nil {
			return err
		}
		rest = rest[k:]
	}
	return nil
}

// Assembler rebuilds one message from Data frame payloads. It grows its
// buffer only as bytes arrive, never to a declared length up front, so a
// hostile prefix cannot make it allocate.
type Assembler struct {
	max   int
	want  int
	have  []byte
	begun bool
}

// NewAssembler accepts messages of at most max bytes (capped at MaxMessage).
func NewAssembler(max int) *Assembler {
	if max <= 0 || max > MaxMessage {
		max = MaxMessage
	}
	return &Assembler{max: max}
}

// Add feeds one Data payload. It returns the whole message when it is
// complete, nil while more is needed. A message longer than its prefix
// said, or a prefix over the cap, is ErrMessage.
func (a *Assembler) Add(chunk []byte) ([]byte, error) {
	if !a.begun {
		if len(chunk) < messagePrefix {
			return nil, fmt.Errorf("%w: short length prefix", ErrMessage)
		}
		n := binary.BigEndian.Uint32(chunk[:messagePrefix])
		if uint64(n) > uint64(a.max) {
			return nil, fmt.Errorf("%w: declared %d bytes over the %d cap", ErrMessage, n, a.max)
		}
		a.want, a.begun = int(n), true
		chunk = chunk[messagePrefix:]
	}
	if len(a.have)+len(chunk) > a.want {
		return nil, fmt.Errorf("%w: more bytes than the prefix declared", ErrMessage)
	}
	a.have = append(a.have, chunk...)
	if len(a.have) < a.want {
		return nil, nil
	}
	msg := a.have
	if msg == nil {
		msg = []byte{}
	}
	a.have, a.want, a.begun = nil, 0, false
	return msg, nil
}

// Pending reports whether a message is partly assembled.
func (a *Assembler) Pending() bool { return a.begun }
