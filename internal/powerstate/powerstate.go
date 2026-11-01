package powerstate

import "strings"

// State is the machine's power source.
type State string

// The State values.
const (
	// AC: on mains power, or a machine with no battery at all.
	AC State = "ac"
	// Battery: running on battery.
	Battery State = "battery"
	// Unknown: the power state could not be read on this OS or host.
	Unknown State = "unknown"
)

// Supply is one power supply as the OS describes it (Linux sysfs vocabulary:
// Type "Mains", "USB", "Battery", ...; Online "1" or "0"; Status
// "Charging", "Discharging", "Full", "Not charging", "Unknown"; Scope
// "System", "Device", "Unknown" or empty when the driver does not say).
type Supply struct {
	Type   string
	Online string
	Status string
	// Scope "Device" marks a supply that powers a peripheral (a wireless
	// mouse, a headset, a UPS reporting over HID), not this machine: it is
	// left out of the reading.
	Scope string
}

// isDeviceScoped reports whether s powers a peripheral, not the machine.
func isDeviceScoped(s Supply) bool { return strings.EqualFold(strings.TrimSpace(s.Scope), "Device") }

// supplyRule is one row of the supply table, walked top-down.
type supplyRule struct {
	when  func(ss []Supply) bool
	state State
}

func anySupply(ss []Supply, f func(Supply) bool) bool {
	for _, s := range ss {
		if f(s) {
			return true
		}
	}
	return false
}

func isBattery(s Supply) bool { return strings.EqualFold(s.Type, "Battery") }

// supplyRules: a machine with no battery is on mains; a mains or USB supply
// that is online means mains; a discharging battery means battery; a
// charging, full or not-charging battery means mains; anything else is
// unknown.
var supplyRules = []supplyRule{
	{func(ss []Supply) bool { return !anySupply(ss, isBattery) }, AC},
	{func(ss []Supply) bool {
		return anySupply(ss, func(s Supply) bool { return !isBattery(s) && strings.TrimSpace(s.Online) == "1" })
	}, AC},
	{func(ss []Supply) bool {
		return anySupply(ss, func(s Supply) bool {
			return isBattery(s) && strings.EqualFold(strings.TrimSpace(s.Status), "Discharging")
		})
	}, Battery},
	{func(ss []Supply) bool {
		return anySupply(ss, func(s Supply) bool {
			st := strings.ToLower(strings.TrimSpace(s.Status))
			return isBattery(s) && (st == "charging" || st == "full" || st == "not charging")
		})
	}, AC},
}

// Classify names the power state the supplies show. Supplies scoped to a
// peripheral (Scope "Device") are dropped first, so a discharging mouse
// battery never reads as "on battery" and a machine whose only batteries
// are peripherals reads as on mains.
func Classify(ss []Supply) State {
	system := make([]Supply, 0, len(ss))
	for _, s := range ss {
		if !isDeviceScoped(s) {
			system = append(system, s)
		}
	}
	ss = system
	for _, r := range supplyRules {
		if r.when(ss) {
			return r.state
		}
	}
	return Unknown
}

// Windows reports SYSTEM_POWER_STATUS fields: ACLineStatus 0 offline, 1
// online, 255 unknown; BatteryFlag 128 means no system battery.
func classifyWindows(acLine, batteryFlag byte) State {
	switch {
	case batteryFlag == 128:
		return AC
	case acLine == 1:
		return AC
	case acLine == 0:
		return Battery
	}
	return Unknown
}
