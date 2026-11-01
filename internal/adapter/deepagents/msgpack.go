package deepagents

import (
	"encoding/binary"
	"fmt"
	"math"
)

// msgpack.go is a minimal, allocation-bounded MessagePack reader for the
// LangGraph checkpoint serde (langgraph.checkpoint.serde.jsonplus). dcode's
// sessions.db stores every channel write and every checkpoint blob as
// ormsgpack output: plain msgpack for scalars / arrays / maps, plus a small
// set of application extension types (ext codes 0-7) that wrap a SECOND
// msgpack document describing a Python object.
//
// The decoder deliberately never reconstructs Python objects: an extension
// value is returned as an extValue{Code, Val} where Val is the decoded inner
// document, so the caller (messages.go) can read a pydantic message's field
// dict without importing or executing anything. It is bounded: a depth cap,
// and every declared length is checked against the bytes actually remaining,
// so a corrupt or hostile blob cannot trigger a large allocation.

// maxMsgpackDepth bounds nesting (arrays/maps/extensions) so a malicious
// blob cannot recurse the stack away. Real checkpoint messages nest well
// under 16 levels.
const maxMsgpackDepth = 64

// LangGraph JsonPlusSerializer extension codes
// (langgraph/checkpoint/serde/jsonplus.py). Only the codes whose payload is
// itself a msgpack document are decoded recursively.
const (
	extConstructorSingleArg = 0
	extConstructorPosArgs   = 1
	extConstructorKwArgs    = 2
	extMethodSingleArg      = 3
	extPydanticV1           = 4
	extPydanticV2           = 5
	extNumpyArray           = 6
	extDeltaSnapshot        = 7
)

// extValue is a decoded MessagePack extension. For the LangGraph codes that
// wrap a msgpack document, Val is that document decoded; for any other code
// Val is the raw []byte payload.
type extValue struct {
	Code int8
	Val  any
}

// object returns the (module, class, payload) triple of a constructor-style
// extension (codes 0-5): the inner document is a list whose first two items
// are the Python module and class name and whose third is the constructor
// argument(s) / pydantic field dict. ok is false for any other shape.
func (e extValue) object() (module, class string, payload any, ok bool) {
	switch e.Code {
	case extConstructorSingleArg, extConstructorPosArgs, extConstructorKwArgs,
		extMethodSingleArg, extPydanticV1, extPydanticV2:
	default:
		return "", "", nil, false
	}
	list, isList := e.Val.([]any)
	if !isList || len(list) < 3 {
		return "", "", nil, false
	}
	module, mok := list[0].(string)
	class, cok := list[1].(string)
	if !mok || !cok {
		return "", "", nil, false
	}
	return module, class, list[2], true
}

// msgpackDecoder walks one buffer.
type msgpackDecoder struct {
	b   []byte
	pos int
}

// decodeMsgpack decodes exactly one MessagePack value from b. Trailing bytes
// are an error: a LangGraph blob is a single document.
func decodeMsgpack(b []byte) (any, error) {
	d := &msgpackDecoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, fmt.Errorf("deepagents.decodeMsgpack: %w", err)
	}
	if d.pos != len(b) {
		return nil, fmt.Errorf("deepagents.decodeMsgpack: %d trailing bytes", len(b)-d.pos)
	}
	return v, nil
}

func (d *msgpackDecoder) need(n int) error {
	if n < 0 || d.pos+n > len(d.b) {
		return fmt.Errorf("truncated: need %d bytes at offset %d of %d", n, d.pos, len(d.b))
	}
	return nil
}

func (d *msgpackDecoder) take(n int) ([]byte, error) {
	if err := d.need(n); err != nil {
		return nil, err
	}
	out := d.b[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *msgpackDecoder) u8() (uint8, error) {
	b, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *msgpackDecoder) uN(n int) (uint64, error) {
	b, err := d.take(n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(b)), nil
	default:
		return binary.BigEndian.Uint64(b), nil
	}
}

// value decodes the next value. depth is the current container nesting.
func (d *msgpackDecoder) value(depth int) (any, error) {
	if depth > maxMsgpackDepth {
		return nil, fmt.Errorf("nesting deeper than %d", maxMsgpackDepth)
	}
	tag, err := d.u8()
	if err != nil {
		return nil, err
	}
	switch {
	case tag <= 0x7f: // positive fixint
		return int64(tag), nil
	case tag >= 0xe0: // negative fixint
		return int64(int8(tag)), nil
	case tag >= 0xa0 && tag <= 0xbf: // fixstr
		return d.str(int(tag & 0x1f))
	case tag >= 0x90 && tag <= 0x9f: // fixarray
		return d.array(int(tag&0x0f), depth)
	case tag >= 0x80 && tag <= 0x8f: // fixmap
		return d.mapOf(int(tag&0x0f), depth)
	}
	switch tag {
	case 0xc0:
		return nil, nil
	case 0xc2:
		return false, nil
	case 0xc3:
		return true, nil
	case 0xc4, 0xc5, 0xc6: // bin 8/16/32
		n, err := d.length(tag - 0xc4)
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	case 0xc7, 0xc8, 0xc9: // ext 8/16/32
		n, err := d.length(tag - 0xc7)
		if err != nil {
			return nil, err
		}
		return d.ext(n, depth)
	case 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3:
		return d.number(tag)
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1/2/4/8/16
		return d.ext(1<<(tag-0xd4), depth)
	case 0xd9, 0xda, 0xdb: // str 8/16/32
		n, err := d.length(tag - 0xd9)
		if err != nil {
			return nil, err
		}
		return d.str(n)
	case 0xdc, 0xdd: // array 16/32
		n, err := d.length(tag - 0xdc + 1)
		if err != nil {
			return nil, err
		}
		return d.array(n, depth)
	case 0xde, 0xdf: // map 16/32
		n, err := d.length(tag - 0xde + 1)
		if err != nil {
			return nil, err
		}
		return d.mapOf(n, depth)
	}
	return nil, fmt.Errorf("unsupported msgpack tag 0x%02x at offset %d", tag, d.pos-1)
}

// number decodes the fixed-width numeric tags 0xca..0xd3 (float32/64,
// uint 8/16/32/64, int 8/16/32/64). Split out of value to keep its
// cyclomatic complexity under the lint threshold; behaviour is unchanged.
func (d *msgpackDecoder) number(tag byte) (any, error) {
	switch tag {
	case 0xca: // float32
		u, err := d.uN(4)
		if err != nil {
			return nil, err
		}
		return float64(math.Float32frombits(uint32(u))), nil
	case 0xcb: // float64
		u, err := d.uN(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(u), nil
	case 0xcc, 0xcd, 0xce, 0xcf: // uint 8/16/32/64
		u, err := d.uN(1 << (tag - 0xcc))
		if err != nil {
			return nil, err
		}
		if u > math.MaxInt64 {
			return float64(u), nil
		}
		return int64(u), nil
	case 0xd0: // int8
		u, err := d.uN(1)
		return int64(int8(u)), err
	case 0xd1:
		u, err := d.uN(2)
		return int64(int16(u)), err
	case 0xd2:
		u, err := d.uN(4)
		return int64(int32(u)), err
	default: // 0xd3, int64
		u, err := d.uN(8)
		return int64(u), err
	}
}

// length reads a big-endian length whose width is 1<<widthExp bytes
// (widthExp 0=1B, 1=2B, 2=4B), validating it against the bytes remaining so
// a forged length cannot drive an allocation.
func (d *msgpackDecoder) length(widthExp uint8) (int, error) {
	u, err := d.uN(1 << widthExp)
	if err != nil {
		return 0, err
	}
	if u > uint64(len(d.b)) {
		return 0, fmt.Errorf("declared length %d exceeds buffer of %d", u, len(d.b))
	}
	return int(u), nil
}

func (d *msgpackDecoder) str(n int) (any, error) {
	b, err := d.take(n)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (d *msgpackDecoder) array(n, depth int) (any, error) {
	// Every element costs at least one byte, so n beyond the remaining bytes
	// is a corrupt header.
	if n > len(d.b)-d.pos {
		return nil, fmt.Errorf("array of %d elements exceeds %d remaining bytes", n, len(d.b)-d.pos)
	}
	out := make([]any, 0, n)
	for i := 0; i < n; i++ {
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (d *msgpackDecoder) mapOf(n, depth int) (any, error) {
	// A pair costs at least two bytes.
	if n*2 > len(d.b)-d.pos {
		return nil, fmt.Errorf("map of %d pairs exceeds %d remaining bytes", n, len(d.b)-d.pos)
	}
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		k, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		// ormsgpack runs with OPT_NON_STR_KEYS, so a key may be an int;
		// canonicalise to its decimal form. Container keys cannot occur.
		switch kk := k.(type) {
		case string:
			out[kk] = v
		default:
			out[fmt.Sprint(kk)] = v
		}
	}
	return out, nil
}

// ext reads an extension: one type byte then n payload bytes. The LangGraph
// codes whose payload is a nested msgpack document are decoded recursively;
// anything else keeps its raw bytes.
func (d *msgpackDecoder) ext(n, depth int) (any, error) {
	code, err := d.u8()
	if err != nil {
		return nil, err
	}
	payload, err := d.take(n)
	if err != nil {
		return nil, err
	}
	c := int8(code)
	switch c {
	case extConstructorSingleArg, extConstructorPosArgs, extConstructorKwArgs,
		extMethodSingleArg, extPydanticV1, extPydanticV2, extDeltaSnapshot:
		inner := &msgpackDecoder{b: payload}
		v, err := inner.value(depth + 1)
		if err != nil {
			return nil, fmt.Errorf("ext %d payload: %w", c, err)
		}
		if inner.pos != len(payload) {
			return nil, fmt.Errorf("ext %d payload: %d trailing bytes", c, len(payload)-inner.pos)
		}
		return extValue{Code: c, Val: v}, nil
	}
	return extValue{Code: c, Val: append([]byte(nil), payload...)}, nil
}
