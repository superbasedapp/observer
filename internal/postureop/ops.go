package postureop

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Direction bounds which values an organization may force for a key and how
// the forced value merges with the node's own. It is a string so the
// directions travel on the vocabulary wire unchanged (nodegov.Direction is an
// alias of this type).
type Direction string

const (
	// DirFree: the org may set any value; it replaces the node's own.
	DirFree Direction = "free"
	// DirRestrictiveOnly: the org may only force the key's safer value (the
	// row's Safe value), and it replaces the node's own. A string list row
	// (an expanding allow-list such as extra_rw_binds) has the empty list as
	// its safe value.
	DirRestrictiveOnly Direction = "restrictive_only"
	// DirLoweringOnly: the org value is a numeric CEILING. A node whose own
	// positive value is lower keeps it; anything else takes the org's.
	DirLoweringOnly Direction = "lowering_only"
	// DirRaisingOnly: the org value is a numeric FLOOR. A node whose own
	// value is higher keeps it.
	DirRaisingOnly Direction = "raising_only"
	// DirOrderedFilter: the org list removes entries from the node's
	// preference order; it never adds or reorders. Whether the first
	// survivor is weaker is the posture comparison's question, not this
	// operator's.
	DirOrderedFilter Direction = "ordered_filter"
	// DirSetIntersection: the effective set is local AND org. An empty
	// intersection allows nothing and is refused, never read as "any".
	DirSetIntersection Direction = "set_intersection"
	// DirAdditiveMask: the org entries are added to the node's own; a mask
	// can only hide more.
	DirAdditiveMask Direction = "additive_mask"
	// DirRetention: a day count where 0 means forever (the maximum). The
	// org may lengthen, never shorten.
	DirRetention Direction = "retention"
)

// Value kinds, the same names the settings.pin vocabulary uses.
const (
	KindBool       = "bool"
	KindString     = "string"
	KindInt        = "int"
	KindStringList = "string_list"
)

// ErrEmptyIntersection is DirSetIntersection's refusal: an empty result means
// "nothing allowed", never "any".
var ErrEmptyIntersection = errors.New("postureop: the intersection is empty, which allows nothing")

// ErrUnknownDirection is a direction no row of Rules carries. Callers fail
// closed on it (refuse the pin), never treat it as free.
var ErrUnknownDirection = errors.New("postureop: unknown direction")

// Rule is one row of the direction table.
type Rule struct {
	// Dir is the direction this row describes.
	Dir Direction
	// Kinds lists the value kinds the direction applies to. Empty means
	// every kind.
	Kinds []string
	// SafeOnly: the org value must equal the key's Safe value.
	SafeOnly bool
	// NonEmpty: an empty org list is an impossible pin (it would filter
	// every entry or allow nothing).
	NonEmpty bool
	// NonNegative: a negative org number is an impossible pin.
	NonNegative bool
	// Label is the plain-language description the admin console shows.
	Label string
	merge func(local, org any) (any, error)
}

// Rules is the direction table, walked by CheckPin and Merge. Its order is
// the order the admin console lists the directions in.
var Rules = []Rule{
	{Dir: DirFree, Label: "the organization may set any value", merge: replace},
	{Dir: DirRestrictiveOnly, Kinds: []string{KindBool, KindString, KindStringList}, SafeOnly: true, Label: "the organization may only force the safer value", merge: replace},
	{Dir: DirLoweringOnly, Kinds: []string{KindInt}, NonNegative: true, Label: "the organization value is a ceiling", merge: intMerge(LowerInt)},
	{Dir: DirRaisingOnly, Kinds: []string{KindInt}, NonNegative: true, Label: "the organization value is a floor", merge: intMerge(RaiseInt)},
	{Dir: DirRetention, Kinds: []string{KindInt}, NonNegative: true, Label: "the organization may lengthen retention, never shorten it (0 keeps forever)", merge: intMerge(RaiseRetention)},
	{Dir: DirOrderedFilter, Kinds: []string{KindStringList}, NonEmpty: true, Label: "the organization list removes entries from the node's order", merge: listMerge(func(l, o []string) ([]string, error) { return OrderedFilter(l, o), nil })},
	{Dir: DirSetIntersection, Kinds: []string{KindStringList}, NonEmpty: true, Label: "the node keeps only entries the organization also allows", merge: listMerge(func(l, o []string) ([]string, error) { return SetIntersection(l, len(l) == 0, o) })},
	{Dir: DirAdditiveMask, Kinds: []string{KindStringList}, Label: "the organization entries are added to the node's own", merge: listMerge(func(l, o []string) ([]string, error) { return AdditiveMask(l, o), nil })},
}

// LookupRule returns the table row for d.
func LookupRule(d Direction) (Rule, bool) {
	for _, r := range Rules {
		if r.Dir == d {
			return r, true
		}
	}
	return Rule{}, false
}

// AppliesTo reports whether the rule accepts values of kind.
func (r Rule) AppliesTo(kind string) bool {
	if len(r.Kinds) == 0 {
		return true
	}
	for _, k := range r.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// CheckPin is the per-key direction check and the impossible-combination
// check, shared by the publish lint and the node's accept path. value must be
// already normalized onto kind (bool, string, int64, []string). It does not
// look at any node's local value: that is the result check's job (Compare).
func CheckPin(d Direction, kind string, value, safe any) error {
	r, ok := LookupRule(d)
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownDirection, d)
	}
	if !r.AppliesTo(kind) {
		return fmt.Errorf("postureop: direction %s does not apply to a %s value", d, kind)
	}
	if r.SafeOnly && !Equal(value, safe) {
		return fmt.Errorf("postureop: may only be set to %v (restrictive-only: the organization may force the safer value, never the riskier one)", safe)
	}
	if r.NonNegative {
		if n, isInt := value.(int64); isInt && n < 0 {
			return fmt.Errorf("postureop: %d is negative, which direction %s cannot express", n, d)
		}
	}
	if r.NonEmpty {
		if l, isList := value.([]string); isList && len(l) == 0 {
			return fmt.Errorf("postureop: an empty list under direction %s would allow nothing", d)
		}
	}
	return nil
}

// Merge composes the node's own value with an org value under direction d.
// Both values must be normalized onto the same kind. An unknown direction is
// an error (fail closed: the caller keeps the node's own value).
func Merge(d Direction, local, org any) (any, error) {
	r, ok := LookupRule(d)
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownDirection, d)
	}
	return r.merge(local, org)
}

func replace(_, org any) (any, error) { return org, nil }

func intMerge(f func(local, org int64) int64) func(local, org any) (any, error) {
	return func(local, org any) (any, error) {
		l, lok := asInt(local)
		o, ook := asInt(org)
		if !lok || !ook {
			return nil, errors.New("postureop: this direction applies to whole numbers only")
		}
		return f(l, o), nil
	}
}

func listMerge(f func(local, org []string) ([]string, error)) func(local, org any) (any, error) {
	return func(local, org any) (any, error) {
		l, lok := local.([]string)
		o, ook := org.([]string)
		if local == nil {
			l, lok = nil, true
		}
		if !lok || !ook {
			return nil, errors.New("postureop: this direction applies to lists of strings only")
		}
		return f(l, o)
	}
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	}
	return 0, false
}

// LowerInt is DirLoweringOnly's merge: a node's own int value under an org
// CEILING. A positive local value below the org's wins, anything else takes
// the org's value. Zero or a negative org value means "no directive" and
// returns local. It is the exact rule config.GovernanceLowerInt has always
// applied.
func LowerInt(local, org int64) int64 {
	if org <= 0 {
		return local
	}
	if local > 0 && local < org {
		return local
	}
	return org
}

// RaiseInt is DirRaisingOnly's merge: the org value is a floor.
func RaiseInt(local, org int64) int64 {
	if org > local {
		return org
	}
	return local
}

// RetentionCmp compares two retention day counts where 0 (or less) is
// forever: -1 when a is shorter than b, 0 when equal, 1 when a is longer.
func RetentionCmp(a, b int64) int {
	ai, bi := a <= 0, b <= 0
	switch {
	case ai && bi:
		return 0
	case ai:
		return 1
	case bi:
		return -1
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// RaiseRetention is DirRetention's merge: the org may lengthen retention (0,
// forever, is the maximum) and may never shorten it, so a local 0 survives
// any finite org value.
func RaiseRetention(local, org int64) int64 {
	if RetentionCmp(org, local) > 0 {
		return org
	}
	return local
}

// OrderedFilter is DirOrderedFilter's merge: the org list removes entries
// from the local preference order; it never adds or reorders.
func OrderedFilter(local, org []string) []string {
	allow := toSet(org)
	out := make([]string, 0, len(local))
	for _, v := range local {
		if allow[v] {
			out = append(out, v)
		}
	}
	return out
}

// SetIntersection is DirSetIntersection's merge. localAny says the local list
// is empty and means "any" (which holds only while no pin is in force). An
// empty result is refused with ErrEmptyIntersection.
func SetIntersection(local []string, localAny bool, org []string) ([]string, error) {
	var out []string
	if localAny {
		out = append(out, org...)
	} else {
		o := toSet(org)
		for _, v := range local {
			if o[v] {
				out = append(out, v)
			}
		}
	}
	out = dedupeSorted(out)
	if len(out) == 0 {
		return nil, ErrEmptyIntersection
	}
	return out, nil
}

// AdditiveMask is DirAdditiveMask's merge: the union, sorted.
func AdditiveMask(local, org []string) []string {
	out := append(append([]string{}, local...), org...)
	return dedupeSorted(out)
}

// Equal compares two normalized values without reflect.DeepEqual's type
// strictness across the int widths a hand-written table might use.
func Equal(a, b any) bool {
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case int64, int, int32:
		x, _ := asInt(av)
		y, ok := asInt(b)
		return ok && x == y
	case []string:
		bv, ok := b.([]string)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	}
	return false
}

func toSet(v []string) map[string]bool {
	s := make(map[string]bool, len(v))
	for _, x := range v {
		s[x] = true
	}
	return s
}

func dedupeSorted(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	sort.Strings(v)
	out := v[:1]
	for _, x := range v[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

func subset(a, b []string) bool {
	s := toSet(b)
	for _, x := range a {
		if !s[x] {
			return false
		}
	}
	return true
}

func joinSet(v []string) string { return "[" + strings.Join(v, ",") + "]" }
