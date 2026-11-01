package postureop

import (
	"fmt"
	"strconv"
	"strings"
)

// AxisKind is how a posture axis orders its values, weaker to stronger.
type AxisKind int

const (
	// AxisEnum is a closed ordered set, Order[0] the weakest.
	AxisEnum AxisKind = iota
	// AxisHigherStronger is a number where a larger value is stricter (a
	// quick-scan budget, an ABI floor).
	AxisHigherStronger
	// AxisLowerStronger is a number where a smaller value is stricter (a
	// staleness bound, a database age).
	AxisLowerStronger
	// AxisRetention is a day count where 0 means forever and longer is
	// stronger (data the developer keeps).
	AxisRetention
	// AxisSubsetStronger is a set where fewer members is stricter (an
	// allow-list, the enabled backends).
	AxisSubsetStronger
	// AxisSupersetStronger is a set where more members is stricter
	// (required components, masks).
	AxisSupersetStronger
	// AxisVersion is a dotted numeric version where newer is stronger (a
	// rule pack floor).
	AxisVersion
)

// Axis is one posture axis a module supplies as data.
type Axis struct {
	// Name identifies the axis in a refusal (posture_loosened names it).
	Name string
	// Kind orders the axis.
	Kind AxisKind
	// Order is the AxisEnum value order, weakest first.
	Order []string
}

// Value is a node's value on one axis. Exactly one field is meaningful per
// AxisKind: S for AxisEnum and AxisVersion, N for the numbers and retention,
// Set for the sets.
type Value struct {
	S   string
	N   int64
	Set []string
}

// Posture is a node's value on every axis, keyed by Axis.Name.
type Posture map[string]Value

// Loosening names an axis an update made weaker.
type Loosening struct {
	Axis   string
	Before string
	After  string
	Reason string
}

// String renders the loosening for a refusal message.
func (l Loosening) String() string {
	return fmt.Sprintf("%s: %s -> %s (%s)", l.Axis, l.Before, l.After, l.Reason)
}

// Compare returns every axis, in the order axes lists them, on which after is
// weaker than before. An axis missing from after while present in before, or
// a value the axis cannot order (an unknown enum value, a malformed version),
// counts as a loosening: fail closed. An axis absent from before has nothing
// to loosen and is skipped. An empty result means the update may apply.
func Compare(axes []Axis, before, after Posture) []Loosening {
	var out []Loosening
	for _, ax := range axes {
		b, hb := before[ax.Name]
		if !hb {
			continue
		}
		a, ha := after[ax.Name]
		if !ha {
			out = append(out, Loosening{Axis: ax.Name, Before: show(ax, b), After: "(missing)", Reason: "axis missing after the update"})
			continue
		}
		ok, err := atLeastAsStrict(ax, b, a)
		switch {
		case err != nil:
			out = append(out, Loosening{Axis: ax.Name, Before: show(ax, b), After: show(ax, a), Reason: err.Error()})
		case !ok:
			out = append(out, Loosening{Axis: ax.Name, Before: show(ax, b), After: show(ax, a), Reason: "weaker"})
		}
	}
	return out
}

// FirstLoosened is Compare's first loosened axis, or "" when the update keeps
// every axis at least as strict. It is what an accept gate names in its
// posture_loosened refusal.
func FirstLoosened(axes []Axis, before, after Posture) (axis string, detail string) {
	l := Compare(axes, before, after)
	if len(l) == 0 {
		return "", ""
	}
	return l[0].Axis, l[0].String()
}

func atLeastAsStrict(ax Axis, before, after Value) (bool, error) {
	switch ax.Kind {
	case AxisEnum:
		bi, ai := indexOf(ax.Order, before.S), indexOf(ax.Order, after.S)
		if bi < 0 || ai < 0 {
			return false, fmt.Errorf("value outside the axis order %v", ax.Order)
		}
		return ai >= bi, nil
	case AxisHigherStronger:
		return after.N >= before.N, nil
	case AxisLowerStronger:
		return after.N <= before.N, nil
	case AxisRetention:
		return RetentionCmp(after.N, before.N) >= 0, nil
	case AxisSubsetStronger:
		return subset(after.Set, before.Set), nil
	case AxisSupersetStronger:
		return subset(before.Set, after.Set), nil
	case AxisVersion:
		c, err := VersionCmp(after.S, before.S)
		return c >= 0, err
	}
	return false, fmt.Errorf("unknown axis kind %d", ax.Kind)
}

// VersionCmp compares dotted numeric versions ("2026.11.1"); a missing
// trailing part reads as 0. A non-numeric part is an error.
func VersionCmp(a, b string) (int, error) {
	pa, err := parseVer(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVer(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int64
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func parseVer(s string) ([]int64, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("version %q is not dotted numbers", s)
		}
		out = append(out, n)
	}
	return out, nil
}

// EnumKey is a setting whose values are an enum, for ReviewEnums.
type EnumKey struct {
	// Key is the setting's dotted name.
	Key string
	// Axis names the posture axis the key's values sit on.
	Axis string
	// Values is every value the setting accepts.
	Values []string
}

// ReviewEnums returns one problem per enum value that has no place on its
// axis, and per key whose axis is unknown or not an enum axis. A module's
// test calls it so a value added to a setting without a direction review
// fails the build's tests (unknown fails closed).
func ReviewEnums(keys []EnumKey, axes []Axis) []string {
	byName := make(map[string]Axis, len(axes))
	for _, a := range axes {
		byName[a.Name] = a
	}
	var bad []string
	for _, k := range keys {
		ax, ok := byName[k.Axis]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s: no axis %q", k.Key, k.Axis))
			continue
		}
		if ax.Kind != AxisEnum {
			bad = append(bad, fmt.Sprintf("%s: axis %q is not an enum axis", k.Key, k.Axis))
			continue
		}
		for _, v := range k.Values {
			if indexOf(ax.Order, v) < 0 {
				bad = append(bad, fmt.Sprintf("%s: value %q has no place on axis %s", k.Key, v, ax.Name))
			}
		}
	}
	return bad
}

func indexOf(order []string, v string) int {
	for i, o := range order {
		if o == v {
			return i
		}
	}
	return -1
}

func show(ax Axis, v Value) string {
	switch ax.Kind {
	case AxisEnum, AxisVersion:
		return v.S
	case AxisSubsetStronger, AxisSupersetStronger:
		return joinSet(v.Set)
	case AxisRetention:
		if v.N <= 0 {
			return "forever"
		}
	}
	return strconv.FormatInt(v.N, 10)
}
