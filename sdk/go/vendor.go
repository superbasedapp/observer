package superbased

import (
	"os"
	"strings"
	"sync"
)

// Vendor tracing states (Diagnostics.VendorTracing).
const (
	VendorTracingOff  = "off"
	VendorTracingKept = "kept"
)

// selfTracing is one model client library that traces itself: under a
// framework instrumentation or a manual LLM span every call would be recorded
// twice. Init turns its switch off unless the app set it, and the pipeline
// drops spans from its tracer scope (a client built before Init).
type selfTracing struct {
	name        string
	env         string // the switch the library reads
	off         string // the switch value that turns its spans off
	scopePrefix string // its tracer's instrumentation scope
}

var selfTracingLibraries = []selfTracing{
	{"anthropic", "ANTHROPIC_OPEN_TELEMETRY", "false", "com.anthropic.sdk"},
}

var (
	vendorMu sync.Mutex
	// name -> the app's own value of the switch, captured at the first Init
	// (nil: unset); later Inits see the value the SDK wrote.
	vendorAppValue = map[string]*string{}
)

// applyVendorTracing turns each library's tracing off unless the app set its
// switch: {name: "off" | "kept"}.
func applyVendorTracing() map[string]string {
	vendorMu.Lock()
	defer vendorMu.Unlock()
	out := map[string]string{}
	for _, lib := range selfTracingLibraries {
		if _, ok := vendorAppValue[lib.name]; !ok {
			if v, set := os.LookupEnv(lib.env); set {
				vendorAppValue[lib.name] = &v
			} else {
				vendorAppValue[lib.name] = nil
			}
		}
		app := vendorAppValue[lib.name]
		switch {
		case app == nil:
			_ = os.Setenv(lib.env, lib.off)
			out[lib.name] = VendorTracingOff
		case strings.ToLower(strings.TrimSpace(*app)) == lib.off:
			out[lib.name] = VendorTracingOff
		default:
			out[lib.name] = VendorTracingKept
		}
	}
	return out
}

// vendorDropPrefixes are the tracer scopes whose spans the pipeline drops.
func vendorDropPrefixes(state map[string]string) []string {
	var out []string
	for _, lib := range selfTracingLibraries {
		if state[lib.name] == VendorTracingOff {
			out = append(out, lib.scopePrefix)
		}
	}
	return out
}

func resetVendorForTests() {
	vendorMu.Lock()
	defer vendorMu.Unlock()
	for _, lib := range selfTracingLibraries {
		if app, ok := vendorAppValue[lib.name]; ok {
			delete(vendorAppValue, lib.name)
			if app == nil {
				_ = os.Unsetenv(lib.env)
			} else {
				_ = os.Setenv(lib.env, *app)
			}
		}
	}
}
