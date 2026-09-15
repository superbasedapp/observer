package archive

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"time"
)

// fieldWriter builds the canonical byte encoding of one row and hashes it with
// FNV-1a/64.
//
// Every variable-length field is LENGTH-PREFIXED rather than separated by a
// delimiter byte. A delimiter is forgeable: a signature excerpt or an import
// specifier containing the delimiter would let two genuinely different rows
// encode identically, and "the checksum matched" would then be a lie exactly
// where the data is most attacker-influenced (raw_text, signature). Length
// prefixes have no such ambiguity.
//
// The encoding is an internal detail with one hard requirement: it must be
// deterministic within a single process run, because both sides of a
// verification are digested by the same binary. It is never persisted, so it
// is free to change between releases.
type fieldWriter struct{ buf []byte }

func (w *fieldWriter) s(v string) *fieldWriter {
	w.buf = binary.AppendUvarint(w.buf, uint64(len(v)))
	w.buf = append(w.buf, v...)
	return w
}

func (w *fieldWriter) b(v []byte) *fieldWriter {
	w.buf = binary.AppendUvarint(w.buf, uint64(len(v)))
	w.buf = append(w.buf, v...)
	return w
}

func (w *fieldWriter) i(v int64) *fieldWriter {
	w.buf = binary.AppendVarint(w.buf, v)
	return w
}

// f encodes a float by its IEEE-754 bit pattern rather than a decimal
// rendering, so a value that does not round-trip through strconv (and NaN,
// which is never equal to itself) still compares byte-for-byte.
func (w *fieldWriter) f(v float64) *fieldWriter {
	w.buf = binary.LittleEndian.AppendUint64(w.buf, math.Float64bits(v))
	return w
}

func (w *fieldWriter) sum() uint64 {
	h := fnv.New64a()
	_, _ = h.Write(w.buf)
	return h.Sum64()
}

// Driver-value type tags. They are written before each value so a NULL, an
// empty string, an empty blob and a zero integer cannot collide into the same
// encoding — which they otherwise would, and NULL-vs-empty is a real
// distinction across the process tables (body_unavailable_reason NULL means
// "a body was captured" while ” means nothing of the kind).
const (
	tagNil byte = iota
	tagInt
	tagFloat
	tagString
	tagBytes
	tagBool
	tagTime
	tagOther
)

// rowDigest hashes one generic driver row, folding in the COLUMN NAMES
// alongside the values.
//
// Hashing the names is what makes the generic path safe. The typed Bucket A
// digests get their column identity from the struct field order, which the
// compiler pins; a generic row has no such pin, so two tables (or two versions
// of one table) with the same values in a different column order would digest
// identically. Including the name in the encoding removes that blind spot —
// and it is exactly the failure a byte-for-byte mirror of an only-copy bucket
// must not have.
func rowDigest(cols []string, vals []any) uint64 {
	var w fieldWriter
	for i, v := range vals {
		if i < len(cols) {
			w.s(cols[i])
		} else {
			w.s("")
		}
		appendDriverValue(&w, v)
	}
	return w.sum()
}

// appendDriverValue encodes one database/sql driver value.
//
// The set of concrete types a driver can hand back is small and fixed by the
// database/sql contract (nil, int64, float64, bool, []byte, string, time.Time);
// the default arm exists so an unexpected type is folded in by its formatted
// form rather than silently ignored — an ignored value is a column that
// verification stops covering.
func appendDriverValue(w *fieldWriter, v any) {
	switch t := v.(type) {
	case nil:
		w.buf = append(w.buf, tagNil)
	case int64:
		w.buf = append(w.buf, tagInt)
		w.i(t)
	case float64:
		w.buf = append(w.buf, tagFloat)
		w.f(t)
	case bool:
		w.buf = append(w.buf, tagBool)
		if t {
			w.i(1)
		} else {
			w.i(0)
		}
	case []byte:
		w.buf = append(w.buf, tagBytes)
		w.b(t)
	case string:
		w.buf = append(w.buf, tagString)
		w.s(t)
	case time.Time:
		w.buf = append(w.buf, tagTime)
		w.i(t.UTC().UnixNano())
	default:
		w.buf = append(w.buf, tagOther)
		w.s(fmt.Sprintf("%T:%v", v, v))
	}
}
