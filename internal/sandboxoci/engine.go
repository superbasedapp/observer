package sandboxoci

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Engine is the container engine behind a socket. The zero value means not
// identified, which no rule accepts.
type Engine string

// The closed Engine vocabulary.
const (
	EngineDocker Engine = "docker"
	EnginePodman Engine = "podman"
)

// Mode is the engine's privilege mode, read from the engine itself (the
// /info security options or Podman's own info), never from the socket path.
type Mode string

// The closed Mode vocabulary.
const (
	ModeRootless Mode = "rootless"
	ModeRootful  Mode = "rootful"
)

// VersionFacts are the fields of GET /version the driver reads.
type VersionFacts struct {
	Version       string
	APIVersion    string
	MinAPIVersion string
	// PlatformName is Platform.Name ("Docker Engine - Community",
	// "Podman Engine").
	PlatformName string
	// Components are the component names ("Engine", "Podman Engine").
	Components []string
}

// InfoFacts are the fields of GET /info the driver reads.
type InfoFacts struct {
	ID              string
	Name            string
	OperatingSystem string
	KernelVersion   string
	DockerRootDir   string
	SecurityOptions []string
	// PodmanRootless is Podman's own host.security.rootless from
	// /libpod/info; nil when not read (Docker, or the call failed).
	PodmanRootless *bool
	// PodmanOCIRuntime is Podman's own host.ociRuntime.name from
	// /libpod/info (the runtime it runs containers with, runc or crun); ""
	// when not read.
	PodmanOCIRuntime string
	// Runtimes is Docker's /info Runtimes map (name -> path and runtime
	// arguments); nil when the engine sent none. The oci-runsc row reads
	// whether runsc is registered and with which --host-uds (runtime.go).
	Runtimes map[string]RuntimeInfo
}

// Identity is who answers on the socket. The probe records it at first
// use and refuses a later answer that differs (socket substitution, A9).
type Identity struct {
	Engine     Engine
	Mode       Mode
	Version    string
	APIVersion string
	// Fingerprint is stable across restarts of the same daemon and
	// different for another daemon on the same path.
	Fingerprint string
	// FingerprintFields are a short digest of each /info fact the
	// fingerprint covers for this engine, keyed by the fact's name, so a
	// changed daemon is refused naming what changed. Empty in an identity
	// recorded before they existed.
	FingerprintFields map[string]string `json:",omitempty"`
	// UsernsRemap: a rootful Docker daemon with userns-remap, which has no
	// row in the uid table.
	UsernsRemap bool
}

// desktopRule is one row of the Docker Desktop table: a field of /info and
// the value that marks Desktop's integration socket (G30).
type desktopRule struct {
	name  string
	match func(InfoFacts) bool
}

// desktopRules marks a socket that is Docker Desktop's VM, which is not a
// same-kernel engine: the WSL2 integration and the macOS and Windows
// installs all report these.
var desktopRules = []desktopRule{
	{"operating system is Docker Desktop", func(i InfoFacts) bool {
		return strings.EqualFold(strings.TrimSpace(i.OperatingSystem), "Docker Desktop")
	}},
	{"engine name is docker-desktop", func(i InfoFacts) bool { return strings.EqualFold(strings.TrimSpace(i.Name), "docker-desktop") }},
	{"kernel is the Desktop VM's linuxkit", func(i InfoFacts) bool { return strings.Contains(strings.ToLower(i.KernelVersion), "linuxkit") }},
}

// IsDesktopVM reports whether the engine is Docker Desktop's VM and which
// rule said so.
func IsDesktopVM(i InfoFacts) (bool, string) {
	for _, r := range desktopRules {
		if r.match(i) {
			return true, r.name
		}
	}
	return false, ""
}

// engineOf names the engine from /version, Podman first because Podman's
// compatible /version also carries an "Engine"-like component.
func engineOf(v VersionFacts) Engine {
	names := append([]string{v.PlatformName}, v.Components...)
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "podman") {
			return EnginePodman
		}
	}
	for _, n := range names {
		l := strings.ToLower(n)
		if strings.Contains(l, "docker") || l == "engine" {
			return EngineDocker
		}
	}
	return ""
}

// hasSecurityOption reports whether opts carries name=<name>.
func hasSecurityOption(opts []string, name string) bool {
	for _, o := range opts {
		for _, part := range strings.Split(o, ",") {
			if strings.TrimSpace(part) == "name="+name {
				return true
			}
		}
	}
	return false
}

// Classify identifies the engine from its /version and /info answers. It
// never guesses: an unknown engine, a Desktop VM or an unreadable version
// is a refusal.
func Classify(v VersionFacts, i InfoFacts) (Identity, Verdict) {
	if desk, why := IsDesktopVM(i); desk {
		return Identity{}, refuse(VerdictEngineIsDesktopVM, "the engine on this socket is Docker Desktop's VM ("+why+"), not a same-kernel engine; the oci-runc row needs Docker Engine or Podman running in this Linux or WSL2 system")
	}
	id := Identity{Engine: engineOf(v), Version: strings.TrimSpace(v.Version), APIVersion: strings.TrimSpace(v.APIVersion)}
	if id.Engine == "" {
		return Identity{}, refuse(VerdictEngineModeUnsupported, "the engine on this socket is neither Docker Engine nor Podman (platform "+quote(v.PlatformName)+")")
	}
	rootless := hasSecurityOption(i.SecurityOptions, "rootless")
	if id.Engine == EnginePodman && i.PodmanRootless != nil {
		rootless = *i.PodmanRootless
	}
	id.Mode = ModeRootful
	if rootless {
		id.Mode = ModeRootless
	}
	id.UsernsRemap = hasSecurityOption(i.SecurityOptions, "userns")
	id.Fingerprint, id.FingerprintFields = fingerprint(id, i)
	return id, pass()
}

// fingerprintField is one /info fact the fingerprint can cover.
type fingerprintField struct {
	name  string
	value func(InfoFacts) string
}

// fingerprintFields are the facts in digest order (the order is part of
// the digest, so an identity recorded before the per-engine table still
// matches on Docker).
var fingerprintFields = []fingerprintField{
	{"engine id", func(i InfoFacts) string { return i.ID }},
	{"host name", func(i InfoFacts) string { return i.Name }},
	{"engine root directory", func(i InfoFacts) string { return i.DockerRootDir }},
}

// stableFingerprintFields are, per engine, the facts that stay the same
// across calls and restarts of one daemon, read from the recorded answers.
// Docker's /info ID is the daemon's persistent engine id (recomputed equal
// on the live check of 2026-10-22). Podman's compatible /info answers a
// fresh random ID on every call (Podman 5.7.0 rootless: "07523748-..." then
// "db60ef60-..." one call apart, live check D2; 5.6 answered ""), so Podman
// counts only its host name and its storage root, which differ between two
// Podman daemons (two users, or rootful and rootless) on one host. The
// socket's device and inode are not used: dockerd and the Podman service
// create a new socket file on every start, so they would refuse every
// restart of the same daemon.
var stableFingerprintFields = map[Engine]map[string]bool{
	EngineDocker: {"engine id": true, "host name": true, "engine root directory": true},
	EnginePodman: {"host name": true, "engine root directory": true},
}

// fingerprint is a stable digest of the daemon's identity over the facts
// stableFingerprintFields names for its engine (a fact the engine does not
// keep stable is hashed as empty), and the per-fact digests.
func fingerprint(id Identity, i InfoFacts) (string, map[string]string) {
	stable := stableFingerprintFields[id.Engine]
	h := sha256.New()
	for _, s := range []string{string(id.Engine), string(id.Mode)} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	fields := map[string]string{}
	for _, f := range fingerprintFields {
		v := ""
		if stable[f.name] {
			v = strings.TrimSpace(f.value(i))
			d := sha256.Sum256([]byte(string(id.Engine) + "\x00" + f.name + "\x00" + v))
			fields[f.name] = hex.EncodeToString(d[:])[:16]
		}
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32], fields
}

// changedIdentityFacts names what differs between a recorded identity and
// the daemon now on the socket, in a fixed order.
func changedIdentityFacts(recorded, now Identity) []string {
	var out []string
	if recorded.Engine != now.Engine {
		out = append(out, "engine")
	}
	if recorded.Mode != now.Mode {
		out = append(out, "privilege mode")
	}
	if len(out) > 0 || recorded.Fingerprint == now.Fingerprint {
		return out
	}
	if len(recorded.FingerprintFields) == 0 {
		return []string{"identity fingerprint (recorded by an older build, so the changed fact is not known)"}
	}
	for _, f := range fingerprintFields {
		a, inA := recorded.FingerprintFields[f.name]
		b, inB := now.FingerprintFields[f.name]
		if inA != inB || a != b {
			out = append(out, f.name)
		}
	}
	if len(out) == 0 {
		out = append(out, "identity fingerprint")
	}
	return out
}

// CompareIdentity is the first-use rule of section 4.6: with nothing
// recorded the answer is recorded (first is true); a recorded identity must
// match the daemon now on the socket, else the socket is untrusted.
func CompareIdentity(recorded Identity, haveRecord bool, now Identity) (first bool, v Verdict) {
	if !haveRecord {
		return true, pass()
	}
	if recorded.Fingerprint != now.Fingerprint || recorded.Engine != now.Engine || recorded.Mode != now.Mode {
		return false, refuse(VerdictSocketUntrusted, "the daemon on this socket is not the one recorded at first use: its "+
			strings.Join(changedIdentityFacts(recorded, now), ", ")+" changed ("+
			string(recorded.Engine)+" "+string(recorded.Mode)+" then, "+string(now.Engine)+" "+string(now.Mode)+" now); run `observer sandbox oci forget-engine` once you have checked it")
	}
	return false, pass()
}
