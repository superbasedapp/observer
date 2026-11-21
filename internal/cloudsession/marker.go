package cloudsession

// LookupEnv is the injected environment lookup (os.LookupEnv in production).
type LookupEnv func(name string) (string, bool)

// Detection is the outcome of walking an agent's cloud-marker table.
type Detection struct {
	// Agent is the agent id the table belonged to.
	Agent string
	// InCloud reports that a marker row matched.
	InCloud bool
	// Location is the matched row's location ("" when nothing matched).
	Location ExecutionLocation
	// MarkerEnv names the variable whose row matched (never its value).
	MarkerEnv string
	// VendorRef is the vendor's cloud session reference, when the agent
	// declares a variable for one and it is set. It is an opaque id, not
	// content (CA-D2).
	VendorRef string
}

// Detect walks agent's marker table top-down with env and returns the first
// matching row's location. An agent with no markers never matches.
func Detect(agent Agent, env LookupEnv) Detection {
	d := Detection{Agent: agent.ID}
	if env == nil {
		return d
	}
	for _, m := range agent.Markers {
		if !envHolds(env, m.Env, m.Equals) {
			continue
		}
		if m.AlsoEnv != "" && !envHolds(env, m.AlsoEnv, m.AlsoEquals) {
			continue
		}
		d.InCloud = true
		d.Location = m.Location
		d.MarkerEnv = m.Env
		break
	}
	if d.InCloud && agent.VendorRefEnv != "" {
		if v, ok := env(agent.VendorRefEnv); ok && validVendorRef(v) {
			d.VendorRef = v
		}
	}
	return d
}

// DetectAny walks every supported agent in table order and returns the first
// detection that is in the cloud. found=false when no marker matched, which
// is what makes flush a no-op on a developer machine.
func DetectAny(env LookupEnv) (Detection, bool) {
	for _, a := range agents {
		if !a.Supported() {
			continue
		}
		if d := Detect(a, env); d.InCloud {
			return d, true
		}
	}
	return Detection{}, false
}

// envHolds reports whether name is set (to want, when want is non-empty).
func envHolds(env LookupEnv, name, want string) bool {
	if name == "" {
		return false
	}
	v, ok := env(name)
	if !ok || v == "" {
		return false
	}
	return want == "" || v == want
}

// maxVendorRefLen bounds a vendor reference; real ones are short ids.
const maxVendorRefLen = 200

// validVendorRef accepts a printable id with no whitespace, so a stray
// multi-line value never reaches a database column.
func validVendorRef(v string) bool {
	if v == "" || len(v) > maxVendorRefLen {
		return false
	}
	for _, r := range v {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// MarkerEnvNames returns the names of the variables Detect reads for agent:
// every marker row's variables and the vendor-reference variable, each once,
// in table order. They name the cloud marker and an opaque session id, never
// a credential, so a process the hooks start may carry them (the loopback
// receiver's minimal environment, cmd/observer otelLoopServeEnv).
func MarkerEnvNames(agent Agent) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, m := range agent.Markers {
		add(m.Env)
		add(m.AlsoEnv)
	}
	add(agent.VendorRefEnv)
	return out
}
