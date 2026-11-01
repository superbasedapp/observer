package proxyroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// portmove.go: moving a route Observer wrote to the daemon's current proxy
// port (operator ruling D-745). The port changes only when someone sets
// [proxy].port (the developer in config, or the org admin through the
// pinnable proxy.port); the routes the organization wrote earlier then still
// name the old port, which the drift reading reports as other_port (T-901).
//
// Under the maintain posture route maintenance moves such a route ONLY when
// Observer provably wrote it. The proof is the route-provenance record, the
// one owner of "who wrote this route" (no second record is kept):
//
//   - the record for this tool and config file is organization-written
//     (routeprov.OrgOwned: enrolment or the managed daemon), read from a
//     readable provenance file (an unreadable file proves nothing);
//   - the route in the file is still exactly the value that record holds;
//   - that value is exactly what the tool's writer writes at the route's own
//     port (routeShape.want), so it differs from the route this daemon would
//     write in the loopback port and nothing else.
//
// Anything else at another local port (no record, a developer's own record,
// a value edited since, a value that differs in more than the port) stays
// other_port drift and is never overwritten. The move edits only the route
// value in place through the same key-preserving edits the Leave removers
// use, re-checks the value right before the edit, and updates the record's
// value so Leave and the admin turning maintenance off still remove it.

// movable adds the port move to a Leave shape.
func movable(s routeShape, want func(routeprov.Record, int) (string, bool), move func(string, routeprov.Record, string) error) routeShape {
	s.want, s.move = want, move
	return s
}

// fixedWant is the want of a tool whose writer writes one fixed URL per port.
func fixedWant(url func(port int) string) func(routeprov.Record, int) (string, bool) {
	return func(_ routeprov.Record, port int) (string, bool) { return url(port), true }
}

// laneAwareWant is the want of a tool with a fixed route and a third-party
// provider lane route (lane.go): a lane record's value is the lane URL for
// the host it replaced, which must give back the recorded lane id.
func laneAwareWant(fixed func(port int) string) func(routeprov.Record, int) (string, bool) {
	return func(rec routeprov.Record, port int) (string, bool) {
		if rec.Lane == "" {
			return fixed(port), true
		}
		id, _, basePath, ok := laneTarget(rec.PriorBaseURL)
		if !ok || id != rec.Lane {
			return "", false
		}
		return laneProxyURL(port, id, basePath), true
	}
}

// ownRouteAt reports whether value is exactly what tool's writer writes for
// rec's route at port. It is the "nothing but the port differs" half of the
// proof; the caller checks the record itself.
func ownRouteAt(tool string, rec routeprov.Record, value string, port int) bool {
	shape, ok := shapeFor(tool)
	if !ok || shape.want == nil || shape.move == nil || value == "" || port <= 0 {
		return false
	}
	want, ok := shape.want(rec, port)
	// The proxy client token form of the route is the same route (OSH-R-009,
	// audit F4): only the port may differ, never the token's presence.
	return ok && proxyauth.WithToken(want, proxyauth.TokenOf(value)) == value
}

// orgWrittenExact reports the full proof for one inspected route: an
// organization record for tool at path whose value is raw, and raw is
// exactly what the writer writes at port (the route's own port).
func (v provenanceView) orgWrittenExact(tool, path, raw string, port int) bool {
	if v.unreadable || v.file == nil || path == "" {
		return false
	}
	rec := v.file.Find(tool, path)
	if rec == nil || !routeprov.OrgOwned(rec.Writer) || rec.Value != raw {
		return false
	}
	return ownRouteAt(tool, *rec, raw, port)
}

// moveRoutePort moves tool's recorded route at path to this registrar's
// proxy port, re-proving ownership first (the file can change between the
// inspection and this write), and records the new value stamped at.
func (r *Registrar) moveRoutePort(tool, path string, at time.Time) error {
	shape, ok := shapeFor(tool)
	if !ok || shape.want == nil || shape.move == nil {
		return fmt.Errorf("proxyroute.moveRoutePort: %s has no route that can be moved", tool)
	}
	if r.opts.Lock != nil {
		unlock, err := r.opts.Lock(path)
		if err != nil {
			return fmt.Errorf("proxyroute.moveRoutePort: lock %s: %w", path, err)
		}
		defer unlock()
	}
	pp := r.ProvenancePath()
	f, err := loadProvenance(pp)
	if err != nil {
		return err
	}
	rec := f.Find(tool, path)
	if rec == nil || !routeprov.OrgOwned(rec.Writer) {
		return fmt.Errorf("proxyroute.moveRoutePort: no organization record for the %s route in %s; nothing was written", tool, path)
	}
	cur, _, err := shape.read(path, rec)
	if err != nil {
		return err
	}
	if cur != rec.Value || !ownRouteAt(tool, *rec, cur, observerURLPort(cur)) {
		return fmt.Errorf("proxyroute.moveRoutePort: the %s route in %s is no longer exactly the one Observer wrote; nothing was written", tool, path)
	}
	to, ok := shape.want(*rec, r.opts.ProxyPort)
	if !ok {
		return fmt.Errorf("proxyroute.moveRoutePort: no %s route for port %d; nothing was written", tool, r.opts.ProxyPort)
	}
	// A route in the client token form moves with its token: only the port
	// changes (audit F4).
	if tok := proxyauth.TokenOf(cur); tok != "" {
		to = proxyauth.WithToken(to, tok)
	}
	if to == cur {
		return nil
	}
	if err := shape.move(path, *rec, to); err != nil {
		return err
	}
	rec.Value = to
	rec.WrittenAt = at.UTC().Format(time.RFC3339)
	return saveProvenance(pp, f)
}

// moveClaudeRouteAt sets env.ANTHROPIC_BASE_URL to `to` when it is still
// rec.Value, keeping every other key (the writer's own serialization).
func moveClaudeRouteAt(path string, rec routeprov.Record, to string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("proxyroute.moveClaudeRouteAt: %s is gone", path)
	}
	if err != nil {
		return fmt.Errorf("proxyroute.moveClaudeRouteAt: read: %w", err)
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return fmt.Errorf("proxyroute.moveClaudeRouteAt: parse %s: %w", path, err)
	}
	env := map[string]any{}
	if e, ok := settings["env"]; ok {
		if err := json.Unmarshal(e, &env); err != nil {
			return fmt.Errorf("proxyroute.moveClaudeRouteAt: parse env: %w", err)
		}
	}
	if cur, _ := env["ANTHROPIC_BASE_URL"].(string); cur != rec.Value {
		return fmt.Errorf("proxyroute.moveClaudeRouteAt: ANTHROPIC_BASE_URL in %s is no longer the value Observer wrote", path)
	}
	env["ANTHROPIC_BASE_URL"] = to
	return writeClaudeEnv(filepath.Dir(path), path, settings, env)
}

// moveCodexRouteAt sets the Observer provider's base_url to `to` when it is
// still rec.Value. The edit is surgical, like removeCodexRouteAt.
func moveCodexRouteAt(path string, rec routeprov.Record, to string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: %s is gone", path)
	}
	if err != nil {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: read: %w", err)
	}
	doc, err := cfgfmt.ParseWith(cfgfmt.FormatTOML, raw, cfgfmt.Options{ForbidReserialize: true})
	if err != nil {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: parse %s: %w", path, err)
	}
	key := cfgfmt.Path{"model_providers", ProviderName, "base_url"}
	cur, _, _ := doc.Get(key)
	if s, _ := cur.(string); s != rec.Value {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: base_url in %s is no longer the value Observer wrote", path)
	}
	if err := doc.Set(key, to); err != nil {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: edit: %w", err)
	}
	if err := writeFileKeepMode(path, doc.Bytes()); err != nil {
		return fmt.Errorf("proxyroute.moveCodexRouteAt: write: %w", err)
	}
	return nil
}

// moveKimiRouteFor sets a recorded Kimi Code route (the lane's recorded key,
// else the fixed [providers.openai].base_url) to `to`.
func moveKimiRouteFor(path string, rec routeprov.Record, to string) error {
	key := kimiBaseURLPath
	if len(rec.RouteKey) > 0 {
		key = cfgfmt.Path(rec.RouteKey)
	}
	return editRouteFile("proxyroute.moveKimiRouteFor", cfgfmt.FormatTOML, path, key, rec.Value, func(doc cfgfmt.Doc) error {
		return doc.Set(key, to)
	})
}

// moveCrushRouteAt sets providers.openai.base_url to `to`.
func moveCrushRouteAt(path string, rec routeprov.Record, to string) error {
	return editRouteFile("proxyroute.moveCrushRouteAt", cfgfmt.FormatJSON, path, crushBaseURLPath, rec.Value, func(doc cfgfmt.Doc) error {
		return doc.Set(crushBaseURLPath, to)
	})
}

// moveQwenRouteFor sets model.baseUrl, and every openai-lane modelProviders
// entry still on the recorded route URL, to `to`.
func moveQwenRouteFor(path string, rec routeprov.Record, to string) error {
	return editRouteFile("proxyroute.moveQwenRouteFor", cfgfmt.FormatJSON, path, qwenBaseURLPath, rec.Value, func(doc cfgfmt.Doc) error {
		if err := doc.Set(qwenBaseURLPath, to); err != nil {
			return err
		}
		return restoreQwenProviders(doc, rec.Value, to)
	})
}
