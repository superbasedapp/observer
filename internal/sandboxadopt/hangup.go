package sandboxadopt

import "time"

// hangup.go is the container helper's choice on a hangup (R-033, audit F2 of
// lane GATES-SBX): stop the container as before, or keep it so the
// daemon's next start can offer the run for re-adoption. A daemon that
// exits while it routes a live run marks the run (DaemonExitMark) just
// before its PTYs close; a user closing the terminal marks nothing.

// HangupGrace bounds how old a daemon-exit mark may be when the hangup
// arrives: a mark older than this is stale (a crash left it, or the user
// closed the terminal much later) and the container is stopped as before.
const HangupGrace = 30 * time.Second

// DaemonExitMark is the file a daemon writes into a live run's re-adoption
// state dir before it exits.
const DaemonExitMark = "daemon-exit"

// HangupFacts are what the helper knows when it is asked to stop.
type HangupFacts struct {
	// Active: the re-adoption component is selected.
	Active bool
	// Kept: the run's plan was kept at launch (the run is re-adoptable).
	Kept bool
	// Marked: the daemon-exit mark is present and owner-only; MarkedAt is
	// when it was written.
	Marked   bool
	MarkedAt time.Time
	// Now is the helper's clock.
	Now time.Time
}

// hangupRules are walked top-down; the first that matches stops the
// container and names why. None matching keeps it.
var hangupRules = []struct {
	why   string
	match func(HangupFacts) bool
}{
	{"the re-adoption component is off", func(f HangupFacts) bool { return !f.Active }},
	{"the run's plan was not kept at launch, so it cannot be re-adopted", func(f HangupFacts) bool { return !f.Kept }},
	{"the hangup is not a daemon exit (the terminal was closed)", func(f HangupFacts) bool { return !f.Marked }},
	{"the daemon-exit mark is stale", func(f HangupFacts) bool {
		age := f.Now.Sub(f.MarkedAt)
		return age < -HangupGrace || age > HangupGrace
	}},
}

// KeepOnHangup decides a hangup: keep reports whether the helper leaves the
// container running for re-adoption; why names the rule that stopped it
// (empty when kept).
func KeepOnHangup(f HangupFacts) (keep bool, why string) {
	for _, r := range hangupRules {
		if r.match(f) {
			return false, r.why
		}
	}
	return true, ""
}
