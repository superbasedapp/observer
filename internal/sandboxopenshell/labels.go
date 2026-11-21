package sandboxopenshell

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The label grammar the labelled reaper selects on (lane O0 R6: killing the
// client does not tear the box down, so every box Observer creates must be
// findable by label alone). OpenShell keeps a sandbox's labels in its own
// store and selects on them with `sandbox list --selector k=v,k=v`; the
// Docker and Podman drivers do not copy them onto the containers.
const (
	// LabelRun carries the Observer run identity of the box (the run id):
	// the fixed key the reaper selects one run's box on.
	LabelRun = "observer.superbased.run"
	// LabelInstall carries this install's id, so a gateway shared with
	// another Observer install never has that install's boxes reaped.
	LabelInstall = "observer.superbased.install"
)

// labelKeyRE is the shape of a label key: a Kubernetes label name segment
// (at most 63 bytes, alphanumeric at both ends, dash, underscore and dot
// inside), with no prefix. OpenShell's own validation is stricter or equal
// for every key this package emits; lane O0's harness ran the hyphenated
// keys observer-o0 and observer-o0-row.
var labelKeyRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)

// labelValueRE is the shape of a label value: the same segment grammar,
// non-empty. It excludes every character the selector syntax uses (",",
// "=", "!", spaces).
var labelValueRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)

// idRE is the shape of a run or install id this package encodes: letters,
// digits, dash and underscore, 8 to 61 bytes (a run id is 16 random bytes in
// base64url, an install id is hex).
var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,61}$`)

// ValidLabelKey reports whether k may be a label key.
func ValidLabelKey(k string) bool { return labelKeyRE.MatchString(k) }

// ValidLabelValue reports whether v may be a label value.
func ValidLabelValue(v string) bool { return labelValueRE.MatchString(v) }

// EncodeID turns a run or install id into a label value. A base64url id can
// start or end with "-" or "_", which a label value cannot, so the value is
// the id between an "o" at each end: deterministic, and the id is the value
// without its first and last byte (DecodeID).
func EncodeID(id string) (string, error) {
	if !idRE.MatchString(id) {
		return "", fmt.Errorf("sandboxopenshell.EncodeID: %q is not a run or install id", id)
	}
	return "o" + id + "o", nil
}

// DecodeID is EncodeID's inverse; ok is false for a value EncodeID did not
// make.
func DecodeID(v string) (string, bool) {
	if len(v) < 2 || v[0] != 'o' || v[len(v)-1] != 'o' {
		return "", false
	}
	id := v[1 : len(v)-1]
	if !idRE.MatchString(id) {
		return "", false
	}
	return id, true
}

// Label is one key and value.
type Label struct {
	Key, Value string
}

// String renders the label as key=value (the --label argument and one
// selector term).
func (l Label) String() string { return l.Key + "=" + l.Value }

// RunLabels returns the labels of one run's box, sorted by key.
func RunLabels(installID, runID string) ([]Label, error) {
	inst, err := EncodeID(installID)
	if err != nil {
		return nil, fmt.Errorf("sandboxopenshell.RunLabels: install: %w", err)
	}
	run, err := EncodeID(runID)
	if err != nil {
		return nil, fmt.Errorf("sandboxopenshell.RunLabels: run: %w", err)
	}
	return []Label{{LabelInstall, inst}, {LabelRun, run}}, nil
}

// InstallLabels returns the selector labels of every box of this install.
func InstallLabels(installID string) ([]Label, error) {
	inst, err := EncodeID(installID)
	if err != nil {
		return nil, fmt.Errorf("sandboxopenshell.InstallLabels: %w", err)
	}
	return []Label{{LabelInstall, inst}}, nil
}

// Selector renders labels as the value of `sandbox list --selector`
// (k1=v1,k2=v2, sorted by key). Every label must pass the grammar.
func Selector(labels []Label) (string, error) {
	if len(labels) == 0 {
		return "", fmt.Errorf("sandboxopenshell.Selector: no label: an empty selector would match every sandbox")
	}
	sorted := append([]Label(nil), labels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	parts := make([]string, 0, len(sorted))
	for i, l := range sorted {
		if err := checkLabel(l); err != nil {
			return "", fmt.Errorf("sandboxopenshell.Selector: %w", err)
		}
		if i > 0 && sorted[i-1].Key == l.Key {
			return "", fmt.Errorf("sandboxopenshell.Selector: key %q twice", l.Key)
		}
		parts = append(parts, l.String())
	}
	return strings.Join(parts, ","), nil
}

// checkLabel checks one label against the grammar.
func checkLabel(l Label) error {
	if !ValidLabelKey(l.Key) {
		return fmt.Errorf("label key %q is not a valid key", l.Key)
	}
	if !ValidLabelValue(l.Value) {
		return fmt.Errorf("label value %q of %s is not a valid value", l.Value, l.Key)
	}
	return nil
}

// ValidRunDirName reports whether name has the shape of a run id this
// package encodes (a run dir under the state dir is named by its run id).
func ValidRunDirName(name string) bool { return idRE.MatchString(name) }
