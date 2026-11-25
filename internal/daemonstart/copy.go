package daemonstart

import (
	"fmt"
	"time"
)

// The copy: one line per outcome, so every launcher prints the same words.
// A start or a wait prints its opening (StartLine, WaitLine), then one dot
// per second while it waits, then one closing (Ready, NotReady, Failed,
// Exited) on the same line. A refusal prints RefuseLine. Every line names
// the launcher the way the launchers' own notices do ("observer claude: ").

// StartLine opens the line for a start. stopped reports that a stop took
// the daemon's routes off (a pending route hold): the line says this launch
// starts it again, since the explicit launch wins over the earlier stop.
func StartLine(label string, m Mechanism, stopped bool) string {
	if stopped {
		return fmt.Sprintf("observer %s: the observer daemon was stopped; starting it again %s ...", label, m.how())
	}
	return fmt.Sprintf("observer %s: the observer daemon was not running; starting it %s ...", label, m.how())
}

// WaitLine opens the line for a wait on a daemon that is already starting.
func WaitLine(label string) string {
	return fmt.Sprintf("observer %s: the observer daemon is starting; waiting for its proxy ...", label)
}

// Ready closes the line: the proxy answered after elapsed.
func Ready(elapsed time.Duration) string {
	return " ready in " + seconds(elapsed)
}

// NotReady closes the line: the proxy did not answer within bound. log names
// where the daemon's output went ("" when unknown).
func NotReady(bound time.Duration, log string) string {
	return " no answer after " + seconds(bound) + logClause(log)
}

// Failed closes the line: the start itself failed.
func Failed(err error, log string) string {
	return fmt.Sprintf(" failed: %v%s", err, logClause(log))
}

// Exited closes the line: the started daemon exited before its proxy
// answered.
func Exited(status string, log string) string {
	return " it exited before its proxy answered (" + status + ")" + logClause(log)
}

// RefuseLine is the one line printed for a refusal row: why no daemon is
// started. port is the proxy port; other is the context the daemon belongs
// to (RuleOtherContext only).
func RefuseLine(label, rule string, port string, other OtherContext) string {
	switch rule {
	case RuleOtherContext:
		return fmt.Sprintf(
			"observer %s: the observer daemon is not running, and this machine's daemon runs in %s; not starting a second one here, which would keep its own database. Start it there: %s.",
			label, other.Where, other.Hint)
	case RuleForeignPort:
		return fmt.Sprintf(
			"observer %s: port %s answers, but not as the Observer proxy; not routing through it, and not starting a daemon that could not bind it. Stop the program on port %s, or set [proxy] port to a free port, then re-run.",
			label, port, port)
	case RulePortHeld:
		return fmt.Sprintf(
			"observer %s: nothing answers on port %s, but the port cannot be bound (another program holds or reserves it); not starting a daemon that could not bind it. Free the port, or set [proxy] port to a free one, then re-run.",
			label, port)
	}
	return ""
}

// logClause is "; log: <path>" or "".
func logClause(log string) string {
	if log == "" {
		return ""
	}
	return "; log: " + log
}

// seconds renders d for the line: "under 1 s", else whole seconds.
func seconds(d time.Duration) string {
	if d < time.Second {
		return "under 1 s"
	}
	return fmt.Sprintf("%d s", int((d+time.Second/2)/time.Second))
}
