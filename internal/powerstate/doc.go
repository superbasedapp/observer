// Package powerstate reads whether this machine runs on mains power or on
// battery, for background work that pauses on battery (security pillar
// plan section 4.4: scanners are "paused on battery by default").
//
// The decision is a pure table (Classify) over the power supplies the OS
// reports; Read is the per-OS boundary: Linux reads
// /sys/class/power_supply, Windows asks GetSystemPowerStatus, and every
// other OS answers Unknown (macOS would need an IOKit call or a pmset
// subprocess, neither of which this package makes). A caller that pauses
// on battery treats Unknown as "may be on battery".
package powerstate
