package supervisor

import "path/filepath"

// The names the deploy/supervisor templates install under.
const (
	// SystemdUnit is deploy/supervisor/observer.service.
	SystemdUnit = "observer.service"
	// LaunchdLabel is deploy/supervisor/app.superbased.observer.plist's Label.
	LaunchdLabel = "app.superbased.observer"
	// WindowsService is the service name deploy/supervisor/README.md uses
	// for both the sc.exe and the NSSM recipes.
	WindowsService = "SuperBasedObserver"
)

// Mechanism names the supervisor that was found.
type Mechanism string

const (
	// MechanismNone: no supervisor was found.
	MechanismNone Mechanism = ""
	// MechanismSystemd: a systemd unit.
	MechanismSystemd Mechanism = "systemd"
	// MechanismLaunchd: a launchd agent or daemon.
	MechanismLaunchd Mechanism = "launchd"
	// MechanismWindowsService: a Windows service.
	MechanismWindowsService Mechanism = "windows_service"
)

// Probe supplies the facts Detect decides on. A nil func reads as "no".
type Probe struct {
	// GOOS is the operating system ("linux", "darwin", "windows").
	GOOS string
	// HomeDir is the user's home directory.
	HomeDir string
	// Getenv reads this process's environment. Only meaningful when the
	// caller IS the daemon (a supervisor sets these for its child).
	Getenv func(key string) string
	// Exists reports whether a file exists.
	Exists func(path string) bool
	// ServiceExists reports whether a Windows service of this name is
	// installed.
	ServiceExists func(name string) bool
}

// Result is what Detect found.
type Result struct {
	// Detected is true when a supervisor was found.
	Detected bool
	// Mechanism names it.
	Mechanism Mechanism
	// Evidence is the fact that matched (an env variable name, a file path,
	// a service name), for doctor's detail line. Never a secret.
	Evidence string
}

type rule struct {
	goos      string
	mechanism Mechanism
	match     func(p Probe) (string, bool)
}

func envSet(key string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		if p.Getenv != nil && p.Getenv(key) != "" {
			return "environment " + key + " is set", true
		}
		return "", false
	}
}

func envEquals(key, want string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		if p.Getenv != nil && p.Getenv(key) == want {
			return "environment " + key + "=" + want, true
		}
		return "", false
	}
}

func fileUnderHome(parts ...string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		if p.HomeDir == "" || p.Exists == nil {
			return "", false
		}
		path := filepath.Join(append([]string{p.HomeDir}, parts...)...)
		return path, p.Exists(path)
	}
}

func fileAt(path string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		return path, p.Exists != nil && p.Exists(path)
	}
}

func service(name string) func(Probe) (string, bool) {
	return func(p Probe) (string, bool) {
		return name, p.ServiceExists != nil && p.ServiceExists(name)
	}
}

// rules is the detection table, walked top-down; the first match wins. The
// environment rows answer "is THIS process supervised" (systemd sets
// INVOCATION_ID for a unit's processes; launchd sets XPC_SERVICE_NAME to the
// job label); the file and service rows answer "is the template installed",
// which is what a separate process such as `observer doctor` can see.
var rules = []rule{
	{"linux", MechanismSystemd, envSet("INVOCATION_ID")},
	{"linux", MechanismSystemd, fileUnderHome(".config", "systemd", "user", SystemdUnit)},
	{"linux", MechanismSystemd, fileAt("/etc/systemd/user/" + SystemdUnit)},
	{"linux", MechanismSystemd, fileAt("/etc/systemd/system/" + SystemdUnit)},
	{"darwin", MechanismLaunchd, envEquals("XPC_SERVICE_NAME", LaunchdLabel)},
	{"darwin", MechanismLaunchd, fileUnderHome("Library", "LaunchAgents", LaunchdLabel+".plist")},
	{"darwin", MechanismLaunchd, fileAt("/Library/LaunchAgents/" + LaunchdLabel + ".plist")},
	{"darwin", MechanismLaunchd, fileAt("/Library/LaunchDaemons/" + LaunchdLabel + ".plist")},
	{"windows", MechanismWindowsService, service(WindowsService)},
}

// Detect walks the table for p.GOOS.
func Detect(p Probe) Result {
	for _, r := range rules {
		if r.goos != p.GOOS {
			continue
		}
		if ev, ok := r.match(p); ok {
			return Result{Detected: true, Mechanism: r.mechanism, Evidence: ev}
		}
	}
	return Result{}
}

// TemplateHint is the one-line pointer doctor and the admin view give when
// no supervisor was found.
const TemplateHint = "install one of the templates in deploy/supervisor/ (systemd user unit, launchd agent, or a Windows service) so the daemon restarts after a crash, a failed update or a reboot"
