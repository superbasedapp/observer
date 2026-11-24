package proxyroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// holdcheck.go: the proof a safe restart takes before it takes a route off
// (the route hold, hold.go).
//
// When the file changes during a restart (the AI tool, the relaunched
// daemon's hook pass, or the developer writes it), or the process that took
// the route off is gone (`observer service stop` then `start`, a restart that
// timed out or was killed), the route is put back by the row's own writer.
// The removal is the row's Leave remover, which can take off more than the
// writer puts back: Codex's remover deletes the whole
// [model_providers.openai-observer] table while the writer writes four keys
// of it, so a developer's own key in that table would be lost. So before a
// route is taken off, the removal and the put-back are rehearsed on a private
// scratch copy of the file, and the route is taken off only when the
// rehearsal gives back every setting of the file: the same values (decoded,
// so key order and spacing do not count) and every full-line comment.
// Otherwise the route stays on through the restart, which risks a failed
// request, never a lost setting.
//
// The rehearsal also yields what the removal leaves at the writer's route
// keys (routeShape.keys). The put-back runs the writer only while those keys
// are still exactly that, so a key the removal set to a value (Qwen Code's
// model.baseUrl goes back to the provider's default host) is not mistaken for
// a route someone set during the restart, and a key someone did change is
// never overwritten.
//
// The scratch copy lives in a private (0700) temporary directory for the
// length of one rehearsal and is removed at once, like the temp file every
// writer here already writes beside the config. Nothing is copied into the
// journal.

// putBackRehearsal is what rehearsing a hold on a scratch copy found.
type putBackRehearsal struct {
	// after is the file the removal leaves.
	after []byte
	// left is the route key's value the removal leaves ("" when it deletes
	// the key).
	left string
	// leftState is routeKeyState of after.
	leftState string
}

// errNotExact is a rehearsal whose put-back would not give the file back.
var errNotExact = errors.New("putting the route back would not give the file back as it was")

// noEnv is an environment with no variables: the scratch home resolves every
// route file under itself.
func noEnv(string) string { return "" }

// rehearsePutBack runs the removal of rm and then the row's writer (as the
// put-back would, with Force and the route's own client token form) on a
// scratch copy of before, and reports what the removal leaves. It returns
// errNotExact (wrapped) when the put-back would not give back every setting
// of before, and any other error when the rehearsal could not run; either way
// the route must stay on.
func (r *Registrar) rehearsePutBack(ri routeInspector, rec *routeprov.Record, rm routeprov.Record, before []byte) (putBackRehearsal, error) {
	shape, ok := shapeFor(ri.tool)
	if !ok || shape.remove == nil || shape.keys == nil || ri.write == nil || ri.path == nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %s has no remover, writer or route keys", ri.tool)
	}
	scratch, err := os.MkdirTemp("", "observer-route-hold-*")
	if err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	sp, err := ri.path(inspectEnv{home: scratch, getenv: noEnv})
	if err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	if !strings.HasPrefix(sp, scratch+string(filepath.Separator)) {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: the %s file does not resolve inside the scratch home", ri.tool)
	}
	if err := os.MkdirAll(filepath.Dir(sp), 0o700); err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	if err := os.WriteFile(sp, before, 0o600); err != nil { //nolint:gosec // G703: sp is checked above to resolve inside the private scratch directory this function created

		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	if err := shape.remove(sp, rm); err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: remove: %w", err)
	}
	var reh putBackRehearsal
	if reh.after, err = os.ReadFile(sp); err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	reh.left, _, err = shape.read(sp, rec)
	if err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	keys := shape.keys(rec)
	if reh.leftState, err = routeKeyState(sp, keys); err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	reg, err := NewRegistrar(RegisterOptions{
		ProxyPort: r.opts.ProxyPort, HomeDir: scratch, Getenv: noEnv,
		ClientToken: proxyauth.TokenOf(rm.Value), Writer: recordWriter(rec), Force: true,
	})
	if err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	if w := ri.write(reg); w.Error != nil || !w.Added {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w: the writer did not write it back", errNotExact)
	}
	back, err := os.ReadFile(sp)
	if err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w", err)
	}
	if now, _, rerr := shape.read(sp, rec); rerr != nil || now != rm.Value {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w: the writer writes another route", errNotExact)
	}
	if err := sameSettings(keys.format, before, back); err != nil {
		return putBackRehearsal{}, fmt.Errorf("proxyroute.rehearsePutBack: %w: %w", errNotExact, err)
	}
	return reh, nil
}

// routeKeyState is the SHA-256 (hex) of the values at the writer's route keys
// in the file at path: a key that is absent, or whose path crosses a value of
// another shape, counts too, so any change to any of them changes the state.
// Only this digest is journaled, never the values.
func routeKeyState(path string, ks routeKeySet) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("proxyroute.routeKeyState: %w", err)
	}
	doc, err := cfgfmt.Parse(ks.format, raw)
	if err != nil {
		// Never quote the file: the decoder's error can carry its bytes.
		return "", fmt.Errorf("proxyroute.routeKeyState: %s does not parse as %s", path, ks.format)
	}
	vals := make([]any, len(ks.paths))
	for i, p := range ks.paths {
		v, found, gerr := doc.Get(p)
		switch {
		case gerr != nil:
			vals[i] = map[string]any{"!shape": true}
		case !found:
			vals[i] = map[string]any{"!absent": true}
		default:
			vals[i] = map[string]any{"value": v}
		}
	}
	b, err := json.Marshal(vals)
	if err != nil {
		return "", fmt.Errorf("proxyroute.routeKeyState: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// sameSettings reports (nil) whether b holds every setting a holds: the same
// decoded values, and every full-line comment of a. It never quotes either.
func sameSettings(f cfgfmt.Format, a, b []byte) error {
	if missing := lostComments(a, b); missing > 0 {
		return fmt.Errorf("%d comment line(s) would be lost", missing)
	}
	switch f {
	case cfgfmt.FormatJSON:
		va, err := decodeJSONExact(a)
		if err != nil {
			return errors.New("the file does not parse as JSON")
		}
		vb, err := decodeJSONExact(b)
		if err != nil {
			return errors.New("the put-back does not parse as JSON")
		}
		if !jsonEqual(va, vb) {
			return errors.New("a setting would differ")
		}
		return nil
	default:
		da, err := cfgfmt.Parse(f, a)
		if err != nil {
			return fmt.Errorf("the file does not parse as %s", f)
		}
		db, err := cfgfmt.Parse(f, b)
		if err != nil {
			return fmt.Errorf("the put-back does not parse as %s", f)
		}
		va, err := da.Value()
		if err != nil {
			return fmt.Errorf("the file does not parse as %s", f)
		}
		vb, err := db.Value()
		if err != nil {
			return fmt.Errorf("the put-back does not parse as %s", f)
		}
		if !reflect.DeepEqual(va, vb) {
			return errors.New("a setting would differ")
		}
		return nil
	}
}

// lostComments counts the full-line comments (# or //) of a that b lacks,
// line for line.
func lostComments(a, b []byte) int {
	have := map[string]int{}
	for _, l := range commentLines(b) {
		have[l]++
	}
	lost := 0
	for _, l := range commentLines(a) {
		if have[l] > 0 {
			have[l]--
			continue
		}
		lost++
	}
	return lost
}

// commentLines returns the trimmed full-line comments of b.
func commentLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			out = append(out, l)
		}
	}
	return out
}

// decodeJSONExact decodes strict JSON keeping every number as written
// (json.Number), so a value a re-serialization would round is noticed.
func decodeJSONExact(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// jsonEqual compares two decodeJSONExact values; numbers compare by exact
// decimal value (1.0 equals 1, 12345678901234567890 does not equal
// 12345678901234567000).
func jsonEqual(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		rx, okx := new(big.Rat).SetString(x.String())
		ry, oky := new(big.Rat).SetString(y.String())
		if !okx || !oky {
			return x == y
		}
		return rx.Cmp(ry) == 0
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !jsonEqual(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !jsonEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}
