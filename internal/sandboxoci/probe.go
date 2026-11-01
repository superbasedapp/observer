package sandboxoci

import (
	"strings"
)

// probe.go is the OCI probe ladder (sandbox plan v2 section 4.7): a pure
// ordered table over injected facts. Each row reads only what the rows
// before it established, so nothing dials a socket until the driver is
// active and the socket passed validation, and the first failing row is the
// verdict. The cmd layer supplies the facts (terminal_sandbox_oci*.go).

// Host is the daemon's host as the probe needs it.
type Host string

// The Host values the ladder distinguishes.
const (
	HostLinux Host = "linux"
	HostWSL2  Host = "wsl2"
	HostOther Host = "other"
)

// WSLTunnelResolver is the resolver address a WSL2 install with DNS
// tunnelling writes into the distro's resolv.conf; a rootless engine's
// slirp4netns namespace cannot reach it (JSP-4 laptop half).
const WSLTunnelResolver = "10.255.255.254"

// WSLDNSStep is the remedy the probe names for engine_cannot_pull.
const WSLDNSStep = "the rootless engine's network namespace cannot reach the WSL2 DNS-tunnelling resolver " + WSLTunnelResolver +
	", so it cannot pull: give the engine a resolver it can reach (for example `dockerd-rootless.sh --dns 1.1.1.1`, or `dns` in daemon.json), " +
	"or load the image from another engine with `docker save` and `docker load`, then try again"

// ProbeConfig is the [terminal.sandbox.oci] subset the ladder reads.
type ProbeConfig struct {
	Socket       string
	Image        string
	AllowRootful bool
	PodmanUserns PodmanUserns
	// ImageRefusal is the signed image trust check's refusal (Observer's
	// default image, or a configured image the project revoked; plan 12.3,
	// lane SBX-P3B); non-empty refuses P10 with artifact_unverified.
	ImageRefusal string
}

// ProbeEnv is the injected I/O. Every func may be nil in a test that stops
// before it is needed; a nil func the ladder reaches is a refusal, never a
// pass.
type ProbeEnv struct {
	Host Host
	// Active: [terminal.sandbox].enabled, the module and the driver active,
	// and oci-runc in [terminal.sandbox].backends. Nothing below runs
	// otherwise.
	Active   bool
	Config   ProbeConfig
	UID, GID uint32
	Groups   []uint32
	Endpoint EndpointEnv
	// StatSocket reads the socket and its parents no-follow.
	StatSocket func(path string) (SocketFacts, error)
	// Query dials the validated socket and reads /version and /info (and
	// /libpod/info on Podman).
	Query func(path string) (VersionFacts, InfoFacts, error)
	// Recorded returns the identity recorded at first use for a socket.
	Recorded func(path string) (Identity, bool)
	// ImagePresent asks the engine whether the image is present locally.
	ImagePresent func(ref string) (bool, error)
	// Resolvers lists the host resolver's nameservers.
	Resolvers func() []string
	// Runtime is the row's runtime column (runtime.go); the zero value is
	// the oci-runc row's.
	Runtime RuntimeProfile
}

// ProbeResult is the ladder's answer plus what it established.
type ProbeResult struct {
	Verdict  Verdict
	Socket   string
	Owner    SocketOwner
	Identity Identity
	User     UserPlan
	Version  VersionStatus
	// FirstUse: no identity was recorded; the caller records Identity.
	FirstUse bool
	// Bridge is how the box reaches the run's host sockets (the runtime
	// row's own probe, P7b).
	Bridge SocketBridge
	// info is the /info answer P5 read, for P7b.
	info InfoFacts
	// Rule is the id of the row that decided.
	Rule string
	// Hint is a known runtime issue on this engine that does not refuse
	// the row (RuntimeHint); "" when none.
	Hint string
}

// probeRow is one ladder row; it fills r or returns a refusal.
type probeRow struct {
	id  string
	run func(env ProbeEnv, r *ProbeResult) Verdict
}

// probeRows is the ladder, walked top-down.
var probeRows = []probeRow{
	{"P1 platform", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.Host != HostLinux && env.Host != HostWSL2 {
			return refuse(VerdictUnsupportedPlatform, "the oci-* backends run on Linux and WSL2 only")
		}
		return pass()
	}},
	{"P2 active", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if !env.Active {
			return refuse(VerdictDisabledByConfig, "the OCI driver is not active, or oci-runc is not in [terminal.sandbox].backends; nothing was probed")
		}
		return pass()
	}},
	{"P3 endpoint", func(env ProbeEnv, r *ProbeResult) Verdict {
		p, v := ResolveEndpoint(env.Config.Socket, env.Endpoint)
		r.Socket = p
		return v
	}},
	{"P4 socket", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.StatSocket == nil {
			return refuse(VerdictEngineUnreachable, "the socket could not be inspected")
		}
		f, err := env.StatSocket(r.Socket)
		if err != nil {
			return refuse(VerdictEngineUnreachable, "the engine socket "+r.Socket+" could not be inspected: "+err.Error())
		}
		owner, v := ValidateSocket(f, env.UID, env.Groups, env.Config.AllowRootful)
		r.Owner = owner
		return v
	}},
	{"P5 engine", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.Query == nil {
			return refuse(VerdictEngineUnreachable, "the engine could not be queried")
		}
		ver, info, err := env.Query(r.Socket)
		if err != nil {
			return refuse(VerdictEngineUnreachable, "the engine on "+r.Socket+" did not answer: "+err.Error())
		}
		id, v := Classify(ver, info)
		r.Identity = id
		r.info = info
		return v
	}},
	{"P6 owner agrees with mode", func(_ ProbeEnv, r *ProbeResult) Verdict { return CheckOwnerMode(r.Owner, r.Identity) }},
	{"P7 version", func(_ ProbeEnv, r *ProbeResult) Verdict {
		st, why := JudgeVersion(r.Identity)
		r.Version = st
		if st == VersionRefused {
			return refuse(VerdictBackendVersionUntested, why)
		}
		return pass()
	}},
	{"P7b runtime", func(env ProbeEnv, r *ProbeResult) Verdict {
		// The row's runtime on this engine: its engine and mode, the
		// runtime registered under its name, and the socket bridge the
		// relay needs (oci-runsc: runsc with --host-uds=open).
		b, v := CheckRuntime(env.Runtime, r.Identity, r.info)
		r.Bridge = b
		if v.OK() {
			r.Hint = RuntimeHint(env.Runtime, r.Identity, r.info)
		}
		return v
	}},
	{"P8 uid table", func(env ProbeEnv, r *ProbeResult) Verdict {
		u, v := PlanUser(r.Identity, int(env.UID), int(env.GID), env.Config.PodmanUserns, env.Config.AllowRootful)
		r.User = u
		return v
	}},
	{"P9 identity", func(env ProbeEnv, r *ProbeResult) Verdict {
		var rec Identity
		var ok bool
		if env.Recorded != nil {
			rec, ok = env.Recorded(r.Socket)
		}
		first, v := CompareIdentity(rec, ok, r.Identity)
		r.FirstUse = first
		return v
	}},
	{"P10 image", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.Config.ImageRefusal != "" {
			return refuse(VerdictArtifactUnverified, env.Config.ImageRefusal)
		}
		if err := ValidateImageRef(env.Config.Image); err != nil {
			return refuse(VerdictImageMissing, err.Error())
		}
		return pass()
	}},
	{"P11 image present", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.ImagePresent == nil {
			return refuse(VerdictImageMissing, "the engine could not be asked for the image")
		}
		ok, err := env.ImagePresent(strings.TrimSpace(env.Config.Image))
		if err != nil {
			return refuse(VerdictEngineUnreachable, "the engine did not answer about the image: "+err.Error())
		}
		if ok {
			return pass()
		}
		if env.Host == HostWSL2 && r.Identity.Mode == ModeRootless && env.Resolvers != nil && contains(env.Resolvers(), WSLTunnelResolver) {
			return refuse(VerdictEngineCannotPull, "the image "+env.Config.Image+" is not present and "+WSLDNSStep)
		}
		return refuse(VerdictImageMissing, "the image "+env.Config.Image+" is not present in the engine; pull it first (`observer sandbox oci pull`, or the engine's own pull)")
	}},
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if strings.TrimSpace(v) == x {
			return true
		}
	}
	return false
}

// Probe walks the ladder.
func Probe(env ProbeEnv) ProbeResult {
	var r ProbeResult
	for _, row := range probeRows {
		v := row.run(env, &r)
		r.Rule = row.id
		if !v.OK() {
			r.Verdict = v
			return r
		}
	}
	r.Verdict = pass()
	return r
}

// PullFailure maps an engine pull error to its verdict: a name-resolution
// or timeout failure of a rootless engine is engine_cannot_pull with the
// DNS step on WSL2; anything else is image_missing with the engine's words.
func PullFailure(host Host, mode Mode, engineMessage string) Verdict {
	l := strings.ToLower(engineMessage)
	dns := false
	for _, w := range []string{"no such host", "server misbehaving", "i/o timeout", "temporary failure in name resolution", "dial udp", "lookup "} {
		dns = dns || strings.Contains(l, w)
	}
	if dns && mode == ModeRootless {
		if host == HostWSL2 {
			return refuse(VerdictEngineCannotPull, "the pull failed resolving the registry ("+engineMessage+"); "+WSLDNSStep)
		}
		return refuse(VerdictEngineCannotPull, "the rootless engine could not resolve the registry ("+engineMessage+"); give its network namespace a reachable resolver, or load the image from another engine")
	}
	return refuse(VerdictImageMissing, "the pull failed: "+engineMessage)
}
