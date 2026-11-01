package proxyroute

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// recorded.go reads back the routes the route-provenance file says Observer
// wrote or confirmed, and reports whether each is still in its config file
// (surface-gap FU-77, the doctor half of audit finding 3). A tool that
// rewrites its whole settings file from memory (Cline's globalState.json,
// written back on every state change while the extension runs) can drop
// Observer's member after the write succeeded; the write side re-checks the
// bytes before its rename (errClineStateMoved), and this is the read side
// that notices the loss afterwards.
//
// It is read-only, dispatches on the tool's route shape (routeShapes, the
// same reader Leave uses, so a lane route is read at its recorded RouteKey),
// never on a tool name, and returns a coarse state per record: never the
// config value, which may sit beside a credential.

// RecordedRouteState is what one recorded route looks like now.
type RecordedRouteState string

const (
	// RecordedRoutePresent: the config file still holds exactly the value
	// Observer recorded.
	RecordedRoutePresent RecordedRouteState = "present"
	// RecordedRouteMissing: the config file is there, but the route member
	// is gone or empty.
	RecordedRouteMissing RecordedRouteState = "missing"
	// RecordedRouteChanged: the route member holds another value than the
	// one Observer recorded (another host, another port, or a value someone
	// set by hand).
	RecordedRouteChanged RecordedRouteState = "changed"
	// RecordedRouteConfigGone: the config file Observer wrote the route into
	// is not there any more (the tool may have been removed from this
	// machine, or its cross-OS home is not mounted). There is no route left
	// to have lost, so a reader should not treat this as a defect.
	RecordedRouteConfigGone RecordedRouteState = "config_gone"
	// RecordedRouteUnreadable: the config file is there but could not be
	// read or parsed. Err says why, in a form that never quotes the file.
	RecordedRouteUnreadable RecordedRouteState = "unreadable"
)

// RecordedRoute is one provenance record and its current state.
type RecordedRoute struct {
	// Tool is the route target label ("cline", "claude-code-windows", ...).
	Tool string
	// ConfigPath is the config file the record names.
	ConfigPath string
	// Setting names where the route lives in that file: the record's
	// RouteKey joined with ".", else the registry's route setting for the
	// tool (integration.RouteSetting), else "".
	Setting string
	// Writer is who wrote or last confirmed the route.
	Writer routeprov.Writer
	// State is the route's current state.
	State RecordedRouteState
	// Err is set for RecordedRouteUnreadable only.
	Err error
}

// recordedReading is what one shape read of a recorded route found.
type recordedReading struct {
	configGone bool
	err        error
	present    bool
	current    string
	recorded   string
}

// recordedRules is the classification table, walked top-down; the first
// match wins.
var recordedRules = []struct {
	match func(r recordedReading) bool
	state RecordedRouteState
}{
	{func(r recordedReading) bool { return r.configGone }, RecordedRouteConfigGone},
	{func(r recordedReading) bool { return r.err != nil }, RecordedRouteUnreadable},
	{func(r recordedReading) bool { return !r.present }, RecordedRouteMissing},
	{func(r recordedReading) bool { return r.current != r.recorded }, RecordedRouteChanged},
	{func(recordedReading) bool { return true }, RecordedRoutePresent},
}

func classifyRecorded(r recordedReading) RecordedRouteState {
	for _, rule := range recordedRules {
		if rule.match(r) {
			return rule.state
		}
	}
	return RecordedRoutePresent
}

// RecordedRoutes reads the route-provenance file a registrar for homeDir
// keeps and reports, for every record whose tool has a route reader, whether
// the recorded value is still at its recorded place. A record whose tool has
// no reader is left out (nothing was looked at, so nothing is claimed). A
// missing provenance file yields none; an unreadable one returns its error
// and none. It never writes.
func RecordedRoutes(homeDir string) ([]RecordedRoute, error) {
	f, err := loadProvenance(filepath.Join(homeDir, ".observer", ProvenanceFileName))
	if err != nil {
		return nil, err
	}
	var out []RecordedRoute
	for i := range f.Records {
		rec := f.Records[i]
		shape, ok := shapeFor(rec.Tool)
		if !ok || shape.read == nil {
			continue
		}
		reading := recordedReading{recorded: rec.Value}
		if _, serr := os.Stat(rec.ConfigPath); errors.Is(serr, os.ErrNotExist) {
			reading.configGone = true
		} else {
			reading.current, reading.present, reading.err = shape.read(rec.ConfigPath, &rec)
		}
		rr := RecordedRoute{
			Tool: rec.Tool, ConfigPath: rec.ConfigPath, Writer: rec.Writer,
			Setting: recordedSetting(rec),
			State:   classifyRecorded(reading),
		}
		if rr.State == RecordedRouteUnreadable {
			rr.Err = reading.err
		}
		out = append(out, rr)
	}
	return out, nil
}

// recordedSetting names where a recorded route lives in its file.
func recordedSetting(rec routeprov.Record) string {
	if len(rec.RouteKey) > 0 {
		return strings.Join(rec.RouteKey, ".")
	}
	return integration.RouteSetting(rec.Tool)
}
