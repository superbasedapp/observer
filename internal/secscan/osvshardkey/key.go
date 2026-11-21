package osvshardkey

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

// Key is one name's shard key: sha256(base || 0x00 || Canon(base, name)).
type Key [sha256.Size]byte

// The bounds of a set's prefix length. 8 is the floor (RM-0 R2: at 8 bits
// an index file holds one entry, so fewer bits would only make index files
// pointless); 16 is past every measured target and keeps an index file
// under MaxIndexBytes.
const (
	MinBits = 8
	MaxBits = 16
)

// Base drops an OSV ecosystem's ":suffix" ("Debian:12" -> "Debian",
// "Red Hat:enterprise_linux:9::baseos" -> "Red Hat"). An ecosystem with no
// suffix is its own base ("npm", "GitHub Actions").
func Base(ecosystem string) string {
	b, _, _ := strings.Cut(ecosystem, ":")
	return b
}

// Canon is the name as it is hashed: lower-cased, after PEP 503 folding
// (every run of '-', '_' and '.' becomes one '-') when base is "PyPI".
// Lower-casing is what keeps GitHub Actions' mixed-case records (7 of 48 at
// RM-0) in the shard of the lower-cased owner/repo the facade compares, and
// both spellings of a NuGet or Go name that the data holds twice in one
// shard.
func Canon(base, name string) string {
	if base == "PyPI" {
		name = pep503Fold(name)
	}
	return strings.ToLower(name)
}

// pep503Fold replaces every run of '-', '_' and '.' with one '-'
// (packaging's canonicalize_name before its lower-casing).
func pep503Fold(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	run := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			if !run {
				b.WriteByte('-')
			}
			run = true
			continue
		}
		run = false
		b.WriteByte(c)
	}
	return b.String()
}

// KeyOf is the shard key of one package name in one base ecosystem. base
// must already be a base (Base); a suffixed ecosystem is not one.
func KeyOf(base, name string) Key {
	h := sha256.New()
	h.Write([]byte(base))
	h.Write([]byte{0})
	h.Write([]byte(Canon(base, name)))
	var k Key
	copy(k[:], h.Sum(nil))
	return k
}

// Prefix is the first bits bits of k, big-endian (bits from MinBits to
// MaxBits; anything else is clamped into that range so the result is
// always a valid prefix of some length, and ValidBits is the check a
// caller makes first).
func (k Key) Prefix(bits int) uint32 {
	bits = clampBits(bits)
	return binary.BigEndian.Uint32(k[:4]) >> (32 - bits)
}

// FirstByte is the first key byte of every key under prefix p of length
// bits: the index file that lists the shard of p.
func FirstByte(p uint32, bits int) int {
	return int(p >> (clampBits(bits) - 8))
}

// ValidBits reports whether bits is a prefix length a set may use.
func ValidBits(bits int) bool { return bits >= MinBits && bits <= MaxBits }

func clampBits(bits int) int {
	if bits < MinBits {
		return MinBits
	}
	if bits > MaxBits {
		return MaxBits
	}
	return bits
}

// PrefixOf is KeyOf(base, name).Prefix(bits).
func PrefixOf(base, name string, bits int) uint32 {
	return KeyOf(base, name).Prefix(bits)
}

// Prefixes is the sorted, distinct set of prefixes of every non-empty name
// given, in one base ecosystem at one prefix length. The node passes every
// spelling it holds for a package (the raw extractor name and its
// reproduction of ParsePackage) and fetches the union; names that fold to
// one canonical form cost one prefix.
func Prefixes(base string, bits int, names ...string) []uint32 {
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		p := PrefixOf(base, n, bits)
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
