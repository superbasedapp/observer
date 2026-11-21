package sandboxrelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Frame types.
const (
	// TypeOpen grants a stream (host to guest only).
	TypeOpen byte = 1
	// TypeData carries stream bytes.
	TypeData byte = 2
	// TypeClose ends a stream (empty payload).
	TypeClose byte = 3
	// TypeWindow grants the peer send credit on a stream (4-byte payload).
	TypeWindow byte = 4
	// TypePing is the heartbeat (stream 0, at most 64 bytes).
	TypePing byte = 5
	// TypeRekey announces the next key epoch (host to guest only).
	TypeRekey byte = 6
)

// Fixed wire sizes.
const (
	frameMagic   = 0xB9
	frameVersion = 1
	// HeaderSize is the fixed header length.
	HeaderSize = 24
	// MACSize is the HMAC-SHA256 tag length.
	MACSize = 32
	// maxPing bounds a heartbeat payload.
	maxPing = 64
)

// Errors. Every one is fatal for the channel.
var (
	ErrMagic     = errors.New("sandboxrelay: bad magic or version")
	ErrType      = errors.New("sandboxrelay: unknown frame type")
	ErrFlags     = errors.New("sandboxrelay: nonzero flags")
	ErrTooLarge  = errors.New("sandboxrelay: payload over the cap")
	ErrMAC       = errors.New("sandboxrelay: bad MAC")
	ErrSeq       = errors.New("sandboxrelay: replayed, skipped or out-of-order sequence")
	ErrEpoch     = errors.New("sandboxrelay: wrong key epoch")
	ErrStream    = errors.New("sandboxrelay: unknown or closed stream")
	ErrDirection = errors.New("sandboxrelay: frame type not allowed in this direction")
	ErrWindow    = errors.New("sandboxrelay: send window exceeded")
	ErrStreams   = errors.New("sandboxrelay: too many streams")
	ErrState     = errors.New("sandboxrelay: frame out of state")
	ErrShort     = errors.New("sandboxrelay: short buffer")
)

// Header is the decoded fixed part of a frame.
type Header struct {
	Type   byte
	Stream uint32
	Seq    uint64
	Len    uint32
	Epoch  uint32
}

// Limits bound what one direction may send.
type Limits struct {
	// MaxPayload is the hard frame payload cap.
	MaxPayload uint32
	// MaxStreams caps concurrently open streams.
	MaxStreams int
	// InitialWindow is the send credit a stream starts with, in bytes. On
	// the hook stream it is at least one whole message (JSP-3).
	InitialWindow uint32
	// MaxWindow is the most credit a Window frame may leave outstanding.
	MaxWindow uint32
}

// DefaultLimits are the shipped bounds: 64 KiB frames, 16 streams, and a
// window of one maximum hook message plus its prefix.
var DefaultLimits = Limits{
	MaxPayload:    64 << 10,
	MaxStreams:    16,
	InitialWindow: MaxMessage + messagePrefix,
	MaxWindow:     2 * (MaxMessage + messagePrefix),
}

// DecodeHeader parses and checks the fixed fields of b[:HeaderSize]. It
// reads only the header and allocates nothing.
func DecodeHeader(b []byte, lim Limits) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShort
	}
	if b[0] != frameMagic || b[1] != frameVersion {
		return Header{}, ErrMagic
	}
	t := b[2]
	if t < TypeOpen || t > TypeRekey {
		return Header{}, ErrType
	}
	if b[3] != 0 {
		return Header{}, ErrFlags
	}
	h := Header{
		Type:   t,
		Stream: binary.BigEndian.Uint32(b[4:8]),
		Seq:    binary.BigEndian.Uint64(b[8:16]),
		Len:    binary.BigEndian.Uint32(b[16:20]),
		Epoch:  binary.BigEndian.Uint32(b[20:24]),
	}
	if h.Len > lim.MaxPayload {
		return Header{}, ErrTooLarge
	}
	return h, nil
}

// Sealer writes frames in one direction.
type Sealer struct {
	epoch uint32
	seq   uint64
	mac   hash.Hash
}

// NewSealer starts a direction at sequence 1 under key.
func NewSealer(key []byte, epoch uint32) *Sealer {
	return &Sealer{epoch: epoch, mac: hmac.New(sha256.New, key)}
}

// Rekey switches to a new key and epoch; the sequence restarts at 1.
func (s *Sealer) Rekey(key []byte, epoch uint32) {
	s.epoch, s.seq, s.mac = epoch, 0, hmac.New(sha256.New, key)
}

// Seal appends one complete frame to dst.
func (s *Sealer) Seal(dst []byte, t byte, stream uint32, payload []byte) []byte {
	s.seq++
	return SealRaw(dst, s.mac, t, stream, s.seq, s.epoch, payload)
}

// seal2 appends one complete frame whose payload is prefix then payload.
func (s *Sealer) seal2(dst []byte, t byte, stream uint32, prefix, payload []byte) []byte {
	s.seq++
	return sealParts(dst, s.mac, t, stream, s.seq, s.epoch, prefix, payload)
}

// SealRaw builds a frame with explicit fields under the MAC m (tests use it
// to forge sequences and epochs with a valid MAC).
func SealRaw(dst []byte, m hash.Hash, t byte, stream uint32, seq uint64, epoch uint32, payload []byte) []byte {
	return sealParts(dst, m, t, stream, seq, epoch, nil, payload)
}

// sealParts builds a frame whose payload is prefix then payload.
func sealParts(dst []byte, m hash.Hash, t byte, stream uint32, seq uint64, epoch uint32, prefix, payload []byte) []byte {
	start := len(dst)
	var h [HeaderSize]byte
	h[0], h[1], h[2], h[3] = frameMagic, frameVersion, t, 0
	binary.BigEndian.PutUint32(h[4:8], stream)
	binary.BigEndian.PutUint64(h[8:16], seq)
	binary.BigEndian.PutUint32(h[16:20], uint32(len(prefix)+len(payload))) //nolint:gosec // G115: callers bound payloads by Limits.MaxPayload
	binary.BigEndian.PutUint32(h[20:24], epoch)
	dst = append(dst, h[:]...)
	dst = append(dst, prefix...)
	dst = append(dst, payload...)
	m.Reset()
	m.Write(dst[start:])
	return m.Sum(dst)
}

// Role is which end decodes.
type Role int

const (
	// HostSide decodes guest-to-host frames (the hostile direction).
	HostSide Role = iota
	// GuestSide decodes host-to-guest frames.
	GuestSide
)

type streamState struct {
	credit uint32 // bytes the peer may still send on this stream
	closed bool
}

// Opener verifies and checks the frames received in one direction and owns
// that direction's per-stream state machine.
type Opener struct {
	role    Role
	lim     Limits
	epoch   uint32
	nextSeq uint64
	mac     hash.Hash
	sum     [MACSize]byte
	streams map[uint32]*streamState
	pending *pendingKey
	// verified is set once a frame has passed its MAC and sequence checks.
	verified bool
}

type pendingKey struct {
	epoch uint32
	key   []byte
}

// NewOpener starts a receiving direction at sequence 1 under key.
func NewOpener(role Role, key []byte, epoch uint32, lim Limits) *Opener {
	return &Opener{role: role, lim: lim, epoch: epoch, nextSeq: 1, mac: hmac.New(sha256.New, key), streams: map[uint32]*streamState{}}
}

// Verified reports whether any frame has passed its MAC and sequence
// checks in this direction: before one has, the peer has proven nothing.
func (o *Opener) Verified() bool { return o.verified }

// Grant registers a stream the HOST opened, so the guest may send on it
// (host side only; the guest never opens streams). Stream 0 is reserved
// for heartbeats.
func (o *Opener) Grant(stream uint32) error {
	if stream == 0 {
		return ErrStream
	}
	if len(o.streams) >= o.lim.MaxStreams {
		return ErrStreams
	}
	if _, ok := o.streams[stream]; ok {
		return ErrState
	}
	o.streams[stream] = &streamState{credit: o.lim.InitialWindow}
	return nil
}

// Rekey arms the next epoch's key; it takes effect when the peer's first
// frame of that epoch arrives (whose sequence restarts at 1).
func (o *Opener) Rekey(key []byte, epoch uint32) {
	o.pending = &pendingKey{epoch: epoch, key: key}
}

// Open verifies one complete frame in buf (header, payload and MAC) and
// applies the direction rules. The payload is a subslice of buf.
func (o *Opener) Open(buf []byte) (Header, []byte, error) {
	h, err := DecodeHeader(buf, o.lim)
	if err != nil {
		return Header{}, nil, err
	}
	total := HeaderSize + int(h.Len) + MACSize
	if len(buf) != total {
		return Header{}, nil, ErrShort
	}
	body := buf[:HeaderSize+int(h.Len)]
	tag := buf[HeaderSize+int(h.Len):]
	m, fromPending := o.mac, false
	if h.Epoch != o.epoch {
		if o.pending == nil || h.Epoch != o.pending.epoch {
			return Header{}, nil, ErrEpoch
		}
		m, fromPending = hmac.New(sha256.New, o.pending.key), true
	}
	m.Reset()
	m.Write(body)
	if !hmac.Equal(m.Sum(o.sum[:0]), tag) {
		return Header{}, nil, ErrMAC
	}
	if fromPending {
		o.epoch, o.mac, o.nextSeq, o.pending = o.pending.epoch, m, 1, nil
	}
	if h.Seq != o.nextSeq {
		return Header{}, nil, ErrSeq
	}
	o.nextSeq++
	o.verified = true
	payload := buf[HeaderSize : HeaderSize+int(h.Len)]
	if err := o.apply(h, payload); err != nil {
		return Header{}, nil, err
	}
	return h, payload, nil
}

func (o *Opener) apply(h Header, payload []byte) error {
	switch h.Type {
	case TypePing:
		if h.Stream != 0 || h.Len > maxPing {
			return ErrState
		}
		return nil
	case TypeOpen, TypeRekey:
		if o.role == HostSide {
			return ErrDirection // a guest never opens streams or re-keys
		}
		if h.Type == TypeOpen {
			if h.Len != 0 {
				return ErrState
			}
			return o.Grant(h.Stream)
		}
		return nil
	}
	st, ok := o.streams[h.Stream]
	if !ok || st.closed {
		return ErrStream
	}
	switch h.Type {
	case TypeData:
		if h.Len > st.credit {
			return ErrWindow
		}
		st.credit -= h.Len
	case TypeClose:
		if h.Len != 0 {
			return ErrState
		}
		st.closed = true
	case TypeWindow:
		if h.Len != 4 {
			return ErrState
		}
		// A Window frame grants credit to OUR sends; only its bound is
		// checked here.
		if binary.BigEndian.Uint32(payload) > o.lim.MaxWindow {
			return ErrWindow
		}
	default:
		return ErrType
	}
	return nil
}

// AddCredit is called when this side's consumer has drained n bytes of a
// stream and a Window frame is sent to the peer.
func (o *Opener) AddCredit(stream uint32, n uint32) error {
	st, ok := o.streams[stream]
	if !ok || st.closed {
		return ErrStream
	}
	if uint64(st.credit)+uint64(n) > uint64(o.lim.MaxWindow) {
		return fmt.Errorf("%w: credit over max", ErrWindow)
	}
	st.credit += n
	return nil
}

// Closed reports whether the peer closed stream.
func (o *Opener) Closed(stream uint32) bool {
	st, ok := o.streams[stream]
	return ok && st.closed
}
