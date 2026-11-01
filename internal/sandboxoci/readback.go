package sandboxoci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// readback.go is the post-build re-check of section 4.4 for the OCI family:
// the host helper reads back what the engine built (GET
// /containers/{id}/json; Podman's own libpod inspect for a Podman engine,
// because only it carries the uid map and the real runtime) and refuses a
// container weaker than the plan with built_below_plan, before the agent
// starts. The parser is strict: a missing, unparsed or unknown field is a
// refusal, never the planned value (a contract test feeds it truncated and
// reshaped answers). The comparison is per engine, as data (JSP-4):
// Podman reports UsernsMode "private" for a keep-id container (so the
// Podman row reads the uid map), and Podman reports CapDrop as its 11
// default capabilities (treated as ALL).
//
// A JSON null is not a missing key. Docker answers null for a list it was
// never sent: an API-created container without devices reads back
// "HostConfig":{"Devices":null} on Docker Engine 26.1.5, 28.1.1, 29.8.2 and
// 29.9.2 (the live checks of 2026-10-22 and the recorded
// inspect_docker_v1.49_*.json), and a bare create reads back null for
// CapDrop, CapAdd, SecurityOpt, Devices, Ulimits and PidsLimit. The list
// fields below therefore decode null as the empty list, and the rule rows
// judge the content: a null Devices is "no devices", which the plan wants,
// and a null CapDrop is "nothing dropped", which the capabilities row
// refuses. Only an absent key is a parse refusal, for the engines that
// always send it (inspectKeysSent).

// MountFact is one entry of the inspect Mounts list.
type MountFact struct {
	Type string
	// Name is a volume's name (empty for a bind or a tmpfs).
	Name        string
	Source      string
	Destination string
	RW          bool
}

// InspectFacts are the fields of a container inspect the re-check reads.
type InspectFacts struct {
	Status         string
	Running        bool
	ExitCode       int
	User           string
	Labels         map[string]string
	NetworkMode    string
	CapDrop        []string
	CapAdd         []string
	SecurityOpt    []string
	ReadonlyRootfs bool
	Privileged     bool
	UsernsMode     string
	// Runtime is the OCI runtime as the engine reports it (Docker:
	// HostConfig.Runtime; Podman: the libpod OCIRuntime).
	Runtime string
	// UIDMap is Podman's HostConfig.IDMappings.UidMap ("container:host:size"
	// entries); nil when absent.
	UIDMap []string
	Mounts []MountFact
	// Tmpfs is HostConfig.Tmpfs.
	Tmpfs map[string]string
	// PidMode, IpcMode and UTSMode are the namespace modes as the engine
	// reports them ("" or "private" for the container's own; "host",
	// "container:<id>" or "ns:<path>" share one).
	PidMode string
	IpcMode string
	UTSMode string
	// Devices are the host devices the engine added (HostConfig.Devices,
	// each "host->container").
	Devices []string
	// PidsLimit is HostConfig.PidsLimit (nil when the engine reports none).
	PidsLimit *int64
}

// wireField is an inspect field whose key may be absent, present as JSON
// null, or carry a value. encoding/json alone folds null and an absent key
// into one nil pointer, which is how a Docker "Devices":null once read as
// a missing field and refused every launch (live checks 2026-10-22, D1).
type wireField[T any] struct {
	// Set: the key was in the answer (with a value or null).
	Set bool
	// Null: the key's value was JSON null.
	Null bool
	V    T
}

// UnmarshalJSON records that the key was present, and whether it was null.
func (f *wireField[T]) UnmarshalJSON(b []byte) error {
	f.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		f.Null = true
		return nil
	}
	return json.Unmarshal(b, &f.V)
}

type deviceWire struct {
	PathOnHost      *string `json:"PathOnHost"`
	PathInContainer *string `json:"PathInContainer"`
}

type mountWire struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type inspectWire struct {
	State *struct {
		Status   *string `json:"Status"`
		Running  *bool   `json:"Running"`
		ExitCode *int    `json:"ExitCode"`
	} `json:"State"`
	Config *struct {
		User   *string                      `json:"User"`
		Labels wireField[map[string]string] `json:"Labels"`
	} `json:"Config"`
	HostConfig *struct {
		NetworkMode    *string             `json:"NetworkMode"`
		CapDrop        wireField[[]string] `json:"CapDrop"`
		CapAdd         []string            `json:"CapAdd"`
		SecurityOpt    wireField[[]string] `json:"SecurityOpt"`
		ReadonlyRootfs *bool               `json:"ReadonlyRootfs"`
		Privileged     *bool               `json:"Privileged"`
		UsernsMode     string              `json:"UsernsMode"`
		Runtime        string              `json:"Runtime"`
		Tmpfs          map[string]string   `json:"Tmpfs"`
		IDMappings     *struct {
			UIDMap []string `json:"UidMap"`
		} `json:"IDMappings"`
		PidMode   *string                 `json:"PidMode"`
		IpcMode   *string                 `json:"IpcMode"`
		UTSMode   *string                 `json:"UTSMode"`
		Devices   wireField[[]deviceWire] `json:"Devices"`
		PidsLimit *int64                  `json:"PidsLimit"`
	} `json:"HostConfig"`
	OCIRuntime string                 `json:"OCIRuntime"`
	Mounts     wireField[[]mountWire] `json:"Mounts"`
}

// inspectKeysSent are the list and map keys each engine always sends in a
// container inspect (null when empty, never omitted): an absent one is a
// reshaped or truncated answer and refuses, while null reads as empty.
// Recorded: Docker API 1.44 to 1.56 (testdata inspect_docker_*.json, the
// v1.49 pair from a live Docker Engine 28.1.1) and Podman's libpod
// inspect 5.6. An engine outside this table has nothing to compare with,
// so its answer refuses as a whole.
var inspectKeysSent = map[Engine][]string{
	EngineDocker: {"Config.Labels", "HostConfig.CapDrop", "HostConfig.SecurityOpt", "HostConfig.Devices", "Mounts"},
	EnginePodman: {"Config.Labels", "HostConfig.CapDrop", "HostConfig.SecurityOpt", "HostConfig.Devices", "Mounts"},
}

// ParseInspect reads an inspect answer strictly: every field the re-check
// needs must be present.
func ParseInspect(raw []byte, engine Engine) (InspectFacts, error) {
	var w inspectWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return InspectFacts{}, fmt.Errorf("sandboxoci: inspect: %w", err)
	}
	missing := func(f string) (InspectFacts, error) {
		return InspectFacts{}, fmt.Errorf("sandboxoci: inspect: field %s is missing", f)
	}
	switch {
	case w.State == nil || w.State.Status == nil || w.State.Running == nil || w.State.ExitCode == nil:
		return missing("State")
	case w.Config == nil || w.Config.User == nil:
		return missing("Config.User")
	case w.HostConfig == nil || w.HostConfig.NetworkMode == nil || w.HostConfig.ReadonlyRootfs == nil || w.HostConfig.Privileged == nil:
		return missing("HostConfig (NetworkMode, ReadonlyRootfs, Privileged)")
	case w.HostConfig.PidMode == nil || w.HostConfig.IpcMode == nil || w.HostConfig.UTSMode == nil:
		return missing("HostConfig (PidMode, IpcMode, UTSMode)")
	}
	sent, ok := inspectKeysSent[engine]
	if !ok {
		return InspectFacts{}, fmt.Errorf("sandboxoci: inspect: no recorded answer shape for engine %q", engine)
	}
	present := map[string]bool{
		"Config.Labels": w.Config.Labels.Set, "HostConfig.CapDrop": w.HostConfig.CapDrop.Set,
		"HostConfig.SecurityOpt": w.HostConfig.SecurityOpt.Set, "HostConfig.Devices": w.HostConfig.Devices.Set,
		"Mounts": w.Mounts.Set,
	}
	for _, k := range sent {
		if !present[k] {
			return missing(k)
		}
	}
	devices, err := parseDevices(w.HostConfig.Devices.V)
	if err != nil {
		return InspectFacts{}, err
	}
	labels := w.Config.Labels.V
	if labels == nil {
		labels = map[string]string{}
	}
	f := InspectFacts{
		Status: *w.State.Status, Running: *w.State.Running, ExitCode: *w.State.ExitCode,
		User: *w.Config.User, Labels: labels,
		NetworkMode: *w.HostConfig.NetworkMode, CapDrop: w.HostConfig.CapDrop.V, CapAdd: w.HostConfig.CapAdd,
		SecurityOpt: w.HostConfig.SecurityOpt.V, ReadonlyRootfs: *w.HostConfig.ReadonlyRootfs, Privileged: *w.HostConfig.Privileged,
		UsernsMode: w.HostConfig.UsernsMode, Runtime: w.HostConfig.Runtime, Tmpfs: w.HostConfig.Tmpfs,
		PidMode: *w.HostConfig.PidMode, IpcMode: *w.HostConfig.IpcMode, UTSMode: *w.HostConfig.UTSMode,
		Devices: devices, PidsLimit: w.HostConfig.PidsLimit,
	}
	if engine == EnginePodman {
		if w.OCIRuntime == "" {
			return missing("OCIRuntime (read the libpod inspect for a Podman engine)")
		}
		f.Runtime = w.OCIRuntime
		if w.HostConfig.IDMappings != nil {
			f.UIDMap = w.HostConfig.IDMappings.UIDMap
		}
	}
	for _, m := range w.Mounts.V {
		f.Mounts = append(f.Mounts, MountFact{Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	return f, nil
}

// parseDevices reads HostConfig.Devices strictly: an empty list (null or
// []) or device mappings that each name a host and a container path. A
// garbled value already failed the decode.
func parseDevices(list []deviceWire) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, d := range list {
		if d.PathOnHost == nil || d.PathInContainer == nil {
			return nil, fmt.Errorf("sandboxoci: inspect: a HostConfig.Devices entry has no host or container path")
		}
		out = append(out, *d.PathOnHost+"->"+*d.PathInContainer)
	}
	return out, nil
}

// privateNamespace reports whether a reported namespace mode is the
// container's own: "" (Docker's default) or "private"; IpcMode also takes
// "shareable" (its own namespace, which another container could join only
// by naming it) and "none" (no shared memory at all). Every other value
// ("host", "container:<id>", "ns:<path>", "pod", a typo) shares a namespace
// and is weaker than planned.
func privateNamespace(mode string, ipc bool) bool {
	switch strings.TrimSpace(mode) {
	case "", "private":
		return true
	case "shareable", "none":
		return ipc
	}
	return false
}

// seccompUnconfinedOpts are the SecurityOpt spellings of a disabled seccomp
// filter (Docker and Podman both report an unconfined profile this way).
var seccompUnconfinedOpts = []string{"seccomp=unconfined", "seccomp:unconfined"}

// podmanDefaultCaps are Podman's 11 default capabilities; Podman reports a
// CapDrop of ALL as this list (JSP-4).
var podmanDefaultCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}

// weakeningSecurityOpts are SecurityOpt values that would undo a default
// confinement.
var weakeningSecurityOpts = []string{"apparmor=unconfined", "apparmor:unconfined", "label=disable", "label:disable", "systempaths=unconfined"}

func normCap(c string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
}

// dropsAll reports whether the dropped set counts as ALL for engine.
func dropsAll(engine Engine, drop []string) bool {
	set := map[string]bool{}
	for _, c := range drop {
		set[normCap(c)] = true
	}
	if set[CapAll] {
		return true
	}
	if engine != EnginePodman {
		return false
	}
	for _, c := range podmanDefaultCaps {
		if !set[c] {
			return false
		}
	}
	return true
}

// ReadBackInput is what one re-check compares.
type ReadBackInput struct {
	Identity Identity
	Plan     CreatePlan
	Facts    InspectFacts
}

// readBackRule is one row of the re-check, walked top-down.
type readBackRule struct {
	name  string
	check func(in ReadBackInput) error
}

// readBackRules is the per-field table. The userns row dispatches on the
// uid plan (data), never on a literal comparison of UsernsMode for Podman.
var readBackRules = []readBackRule{
	{"not privileged", func(in ReadBackInput) error {
		if in.Facts.Privileged {
			return fmt.Errorf("the container is privileged")
		}
		return nil
	}},
	{"network none", func(in ReadBackInput) error {
		if in.Facts.NetworkMode != NetworkNone {
			return fmt.Errorf("network mode is %q, planned %q", in.Facts.NetworkMode, NetworkNone)
		}
		return nil
	}},
	{"capabilities dropped", func(in ReadBackInput) error {
		if !dropsAll(in.Identity.Engine, in.Facts.CapDrop) {
			return fmt.Errorf("capabilities dropped are %v, planned ALL", in.Facts.CapDrop)
		}
		if len(in.Facts.CapAdd) > 0 {
			return fmt.Errorf("capabilities added: %v", in.Facts.CapAdd)
		}
		return nil
	}},
	{"no-new-privileges", func(in ReadBackInput) error {
		ok := false
		for _, o := range in.Facts.SecurityOpt {
			l := strings.ToLower(strings.TrimSpace(o))
			if l == NoNewPrivileges || l == NoNewPrivileges+":true" || l == NoNewPrivileges+"=true" {
				ok = true
			}
			for _, w := range weakeningSecurityOpts {
				if l == w {
					return fmt.Errorf("security option %q undoes a default confinement", o)
				}
			}
		}
		if !ok {
			return fmt.Errorf("no-new-privileges is not set (security options %v)", in.Facts.SecurityOpt)
		}
		return nil
	}},
	{"seccomp", func(in ReadBackInput) error {
		for _, o := range in.Facts.SecurityOpt {
			l := strings.ToLower(strings.TrimSpace(o))
			for _, u := range seccompUnconfinedOpts {
				if l == u {
					return fmt.Errorf("the seccomp profile is unconfined (security option %q), planned the engine's default filter", o)
				}
			}
		}
		return nil
	}},
	{"pid namespace", func(in ReadBackInput) error {
		if !privateNamespace(in.Facts.PidMode, false) {
			return fmt.Errorf("pid mode is %q, planned the container's own", in.Facts.PidMode)
		}
		return nil
	}},
	{"ipc namespace", func(in ReadBackInput) error {
		if !privateNamespace(in.Facts.IpcMode, true) {
			return fmt.Errorf("ipc mode is %q, planned private", in.Facts.IpcMode)
		}
		return nil
	}},
	{"uts namespace", func(in ReadBackInput) error {
		if !privateNamespace(in.Facts.UTSMode, false) {
			return fmt.Errorf("uts mode is %q, planned the container's own", in.Facts.UTSMode)
		}
		return nil
	}},
	{"devices", func(in ReadBackInput) error {
		if len(in.Facts.Devices) > 0 {
			return fmt.Errorf("host devices were added: %v; the plan adds none", in.Facts.Devices)
		}
		return nil
	}},
	{"pids limit", func(in ReadBackInput) error {
		want := in.Plan.PidsLimit
		if want <= 0 {
			return nil
		}
		if in.Facts.PidsLimit == nil || *in.Facts.PidsLimit <= 0 || *in.Facts.PidsLimit > want {
			got := "none"
			if in.Facts.PidsLimit != nil {
				got = fmt.Sprint(*in.Facts.PidsLimit)
			}
			return fmt.Errorf("the pids limit is %s, planned %d", got, want)
		}
		return nil
	}},
	{"read-only root", func(in ReadBackInput) error {
		if in.Plan.ReadonlyRootfs && !in.Facts.ReadonlyRootfs {
			return fmt.Errorf("the root filesystem is writable, planned read-only")
		}
		return nil
	}},
	{"user", func(in ReadBackInput) error {
		if in.Facts.User != in.Plan.User.User {
			return fmt.Errorf("user is %q, planned %q", in.Facts.User, in.Plan.User.User)
		}
		return nil
	}},
	{"user namespace", func(in ReadBackInput) error {
		want := in.Plan.User
		switch {
		case want.ExpectUIDMap != "":
			for _, e := range in.Facts.UIDMap {
				if strings.TrimSpace(e) == want.ExpectUIDMap {
					return nil
				}
			}
			return fmt.Errorf("the uid map %v does not contain %s (keep-id not applied)", in.Facts.UIDMap, want.ExpectUIDMap)
		case in.Identity.Engine == EngineDocker:
			if m := in.Facts.UsernsMode; m != "" && m != "host" {
				return fmt.Errorf("user namespace mode is %q, planned the engine default", m)
			}
		}
		return nil
	}},
	{"runtime", func(in ReadBackInput) error {
		// The planned runtime decides: an engine-default plan (oci-runc)
		// takes the same-kernel runc or crun, a runsc plan (oci-runsc) only
		// a container the engine reports as runsc. Anything else (kata, a
		// runtime the daemon substituted) is another row.
		p := runtimeProfiles[0]
		if in.Plan.Runtime != "" {
			for _, rp := range runtimeProfiles {
				if rp.CreateRuntime == in.Plan.Runtime {
					p = rp
				}
			}
			if p.CreateRuntime != in.Plan.Runtime {
				return fmt.Errorf("planned runtime %q has no row", in.Plan.Runtime)
			}
		}
		if !p.accepts(in.Facts.Runtime) {
			return fmt.Errorf("runtime is %q; the %s row needs %s", in.Facts.Runtime, p.Backend, strings.Join(p.Accept, " or "))
		}
		return nil
	}},
	{"labels", func(in ReadBackInput) error { return checkLabels(in.Plan.InstallID, in.Plan.RunID, in.Facts.Labels) }},
	{"mounts", func(in ReadBackInput) error { return checkMounts(in.Plan, in.Facts, in.Identity.Engine) }},
}

// checkVolume judges one volume mount: an unplanned one (an image's VOLUME
// line) exposes no host path and passes; a planned one (the tool cache) must
// be the planned volume, read-only when planned so.
func checkVolume(vols map[string]VolumeMount, m MountFact, got map[string]bool) error {
	v, ok := vols[m.Destination]
	if !ok {
		return nil
	}
	if m.Name != v.Name {
		return fmt.Errorf("volume at %s is %q, planned %q", m.Destination, m.Name, v.Name)
	}
	if v.ReadOnly && m.RW {
		return fmt.Errorf("volume at %s is writable, planned read-only", m.Destination)
	}
	got[m.Destination] = true
	return nil
}

// checkMounts requires every planned bind with its read-only flag, and
// refuses any host path the plan did not name. Anonymous volumes from an
// image's VOLUME lines and engine tmpfs mounts expose no host path and pass.
// A writable tmpfs must carry the container user as owner in the form of
// the engine that answered (tmpfsOwnerTable).
//
// The plan's pins (a repository folder or .git bound onto itself inside a
// read-write bind, BuildCreate) are planned binds too (Linux live re-check
// on the Docker sandbox 2026-10-23, N1: they were left out of this set, so
// every launch in a git repository was refused as an unplanned bind of its
// .git on both engines). A pin must come back from its own path with
// exactly its planned mode: read-write only when its nearest enclosing
// mount is a read-write bind (nearestPinMount, the planner's restatement of
// sandbox.PinWritable), read-only otherwise. Any other bind still refuses.
func checkMounts(p CreatePlan, f InspectFacts, engine Engine) error {
	want := map[string]Bind{}
	for _, b := range p.Binds {
		want[b.Target] = b
	}
	pins := map[string]bool{}
	for _, pin := range p.Pins {
		want[pin] = Bind{Source: pin, Target: pin, ReadOnly: nearestPinMount(p, pin) != pinUnderWriteBind}
		pins[pin] = true
	}
	for _, h := range p.HideFiles {
		want[h] = Bind{Source: "/dev/null", Target: h, ReadOnly: true}
	}
	vols := map[string]VolumeMount{}
	for _, v := range p.Volumes {
		vols[v.Target] = v
	}
	gotVol := map[string]bool{}
	got := map[string]MountFact{}
	for _, m := range f.Mounts {
		switch m.Type {
		case "bind":
			b, ok := want[m.Destination]
			if !ok {
				return fmt.Errorf("unplanned bind %s -> %s", m.Source, m.Destination)
			}
			if b.Source != m.Source {
				return fmt.Errorf("bind at %s comes from %s, planned %s", m.Destination, m.Source, b.Source)
			}
			if b.ReadOnly && m.RW {
				return fmt.Errorf("bind at %s is writable, planned read-only", m.Destination)
			}
			if pins[m.Destination] && !b.ReadOnly && !m.RW {
				return fmt.Errorf("pin at %s is read-only, planned read-write", m.Destination)
			}
			got[m.Destination] = m
		case "volume":
			if err := checkVolume(vols, m, gotVol); err != nil {
				return err
			}
		case "tmpfs":
		default:
			return fmt.Errorf("unplanned %q mount at %s", m.Type, m.Destination)
		}
	}
	var missing []string
	for t := range want {
		if _, ok := got[t]; !ok {
			missing = append(missing, t)
		}
	}
	for t := range vols {
		if !gotVol[t] {
			missing = append(missing, t)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("planned binds are missing: %s", strings.Join(missing, ", "))
	}
	owner, ok := tmpfsOwnerFor(engine)
	if !ok && len(p.Tmpfs) > 0 {
		return fmt.Errorf("engine %q has no tmpfs owner form", engine)
	}
	uid, gid := userIDs(p.User.User)
	for _, d := range p.Tmpfs {
		opts, ok := f.Tmpfs[d]
		if !ok {
			return fmt.Errorf("planned tmpfs %s is missing", d)
		}
		if !owner.shown(strings.Split(opts, ","), uid, gid) {
			return fmt.Errorf("planned tmpfs %s is not owned by the container user %s (%s answered %q)", d, p.User.User, engine, opts)
		}
	}
	for _, d := range p.HideDirs {
		opts, ok := f.Tmpfs[d]
		if !ok || !strings.HasPrefix(opts, "ro") {
			return fmt.Errorf("planned hiding tmpfs %s is missing or writable", d)
		}
	}
	return nil
}

// ReadBack runs the re-check; a refusal is built_below_plan naming the
// first row that failed.
func ReadBack(in ReadBackInput) Verdict {
	for _, r := range readBackRules {
		if err := r.check(in); err != nil {
			return refuse(VerdictBuiltBelowPlan, r.name+": "+err.Error())
		}
	}
	return pass()
}
