package daemonstart

// Mechanism is how a launcher starts the daemon this install owns. A closed
// vocabulary.
type Mechanism string

// The mechanisms.
const (
	// MechanismSystemd: `systemctl --user start observer.service`, the unit
	// `observer service install` wrote.
	MechanismSystemd Mechanism = "systemd"
	// MechanismLaunchd: the LaunchAgent `observer service install` wrote
	// (bootstrap, or kickstart when it is loaded).
	MechanismLaunchd Mechanism = "launchd"
	// MechanismSignIn: the observer binary the Windows sign-in entry
	// (`observer setup autostart on`) starts, run as `observer start` in the
	// background with the launcher's config.
	MechanismSignIn Mechanism = "sign_in"
	// MechanismDetached: this binary's `observer start`, in the background
	// (its own session on Unix, a detached process on Windows), its output
	// appended to daemon.log beside the database.
	MechanismDetached Mechanism = "detached"
)

// MechanismFacts is what ChooseMechanism reads.
type MechanismFacts struct {
	// SystemdUnit: systemd runs here and Observer's user unit is installed.
	SystemdUnit bool
	// LaunchAgent: launchd runs here and Observer's LaunchAgent is installed.
	LaunchAgent bool
	// ServiceRunsThisConfig: the installed unit or agent runs the config the
	// launcher resolved (its --config, or neither names one). A unit for
	// another config would start a daemon on another database and port.
	ServiceRunsThisConfig bool
	// SignInBinary: the Windows sign-in entry is set and names an install
	// whose observer binary exists.
	SignInBinary bool
}

type mechanismRule struct {
	name  string
	match func(f MechanismFacts) bool
	mech  Mechanism
}

// mechanismRules is the ordered table; one test case per row.
var mechanismRules = []mechanismRule{
	{"systemd user unit", func(f MechanismFacts) bool { return f.SystemdUnit && f.ServiceRunsThisConfig }, MechanismSystemd},
	{"launchd agent", func(f MechanismFacts) bool { return f.LaunchAgent && f.ServiceRunsThisConfig }, MechanismLaunchd},
	{"windows sign-in entry", func(f MechanismFacts) bool { return f.SignInBinary }, MechanismSignIn},
	{"background start", func(MechanismFacts) bool { return true }, MechanismDetached},
}

// ChooseMechanism walks mechanismRules top-down.
func ChooseMechanism(f MechanismFacts) Mechanism {
	for _, r := range mechanismRules {
		if r.match(f) {
			return r.mech
		}
	}
	return MechanismDetached
}

// how names a mechanism in the start line.
func (m Mechanism) how() string {
	switch m {
	case MechanismSystemd:
		return "through its systemd user unit"
	case MechanismLaunchd:
		return "through its launchd agent"
	case MechanismSignIn:
		return "in the background (the install your Windows sign-in entry starts)"
	default:
		return "in the background"
	}
}
