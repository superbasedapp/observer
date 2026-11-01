package sandboxvm

import (
	"encoding/json"
	"errors"
)

// events.go reads Cloud Hypervisor's event monitor (--event-monitor, one
// JSON object per line on an inherited descriptor) for the host helper: a
// lifecycle end ends the run, and every other event triggers an immediate
// vm.info read-back, so a device hot-plugged through the API socket after
// boot (vm.add-fs works, EM spike 2026-10-24) is refused at once rather
// than at the next periodic read.

// maxEventLine caps one event line.
const maxEventLine = 64 << 10

// Event is one event monitor line.
type Event struct {
	Source string `json:"source"`
	Event  string `json:"event"`
}

// EventAction is what the helper does about an event.
type EventAction int

// The actions.
const (
	// EventIgnore: a boot-phase event before the first read-back.
	EventIgnore EventAction = iota
	// EventReadBack: read vm.info back now.
	EventReadBack
	// EventEnded: the VM or the VMM is gone; end the run.
	EventEnded
)

// eventTable is THE event table (source, event) -> action; an event not in
// it reads back.
var eventTable = map[[2]string]EventAction{
	{"vmm", "starting"}:   EventIgnore,
	{"vm", "creating"}:    EventIgnore,
	{"vm", "created"}:     EventIgnore,
	{"vm", "booting"}:     EventIgnore,
	{"vm", "booted"}:      EventReadBack,
	{"vm", "shutdown"}:    EventEnded,
	{"vm", "deleted"}:     EventEnded,
	{"vm", "rebooting"}:   EventEnded,
	{"vm", "rebooted"}:    EventEnded,
	{"vm", "panic"}:       EventEnded,
	{"vmm", "shutdown"}:   EventEnded,
	{"vm", "snapshotted"}: EventReadBack,
}

// ParseEvent decodes one line.
func ParseEvent(line []byte) (Event, error) {
	if len(line) > maxEventLine {
		return Event{}, errors.New("sandboxvm: an event line over the cap")
	}
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return Event{}, err
	}
	if e.Source == "" || e.Event == "" {
		return Event{}, errors.New("sandboxvm: an event without a source or name")
	}
	return e, nil
}

// ActionFor maps an event to the helper's action.
func ActionFor(e Event) EventAction {
	if a, ok := eventTable[[2]string{e.Source, e.Event}]; ok {
		return a
	}
	return EventReadBack
}
