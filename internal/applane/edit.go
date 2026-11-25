package applane

import (
	"errors"
	"fmt"
	"strings"
)

// The lane-edit errors (`observer apps lane add|remove` and the dashboard's
// /api/apps/lanes share them, so both refuse the same things).
var (
	// ErrInvalid wraps a refused id, upstream or model pattern.
	ErrInvalid = errors.New("invalid app lane")
	// ErrExists refuses an add over an existing lane: an add never silently
	// repoints a lane an app already uses.
	ErrExists = errors.New("app lane already exists; remove it first to change its upstream")
	// ErrAgentLane refuses an id that names a coding-agent lane.
	ErrAgentLane = errors.New("the id is a coding-agent lane ([proxy.agent_upstreams]); pick another id")
	// ErrNotFound refuses removing a lane that does not exist.
	ErrNotFound = errors.New("no such app lane")
	// ErrAutoDefault refuses removing the virtual auto lane's default.
	ErrAutoDefault = errors.New("the lane is proxy.auto_default_lane; change that first")
)

// Add is one validated lane to add.
type Add struct {
	ID       string
	Upstream string
	Models   []string
}

// ValidateAdd checks a lane add: a valid id, an upstream (the well-known
// id's default when empty) that is https or http to loopback, and model
// patterns without spaces. It returns the normalised add.
func ValidateAdd(id, upstream string, models []string) (Add, error) {
	a := Add{ID: strings.TrimSpace(id)}
	if !ValidLaneID(a.ID) {
		return Add{}, fmt.Errorf("%w: id %q: use 1-64 of a-z, 0-9, - and _ (not \"auto\")", ErrInvalid, a.ID)
	}
	a.Upstream = strings.TrimRight(strings.TrimSpace(upstream), "/")
	if a.Upstream == "" {
		def, ok := DefaultUpstream(a.ID)
		if !ok {
			return Add{}, fmt.Errorf("%w: lane %q has no default upstream; name one (for example https://api.openai.com)", ErrInvalid, a.ID)
		}
		a.Upstream = def
	}
	if !ValidUpstream(a.Upstream) {
		return Add{}, fmt.Errorf("%w: upstream %q: use an https URL, or http to a loopback host, with no query", ErrInvalid, a.Upstream)
	}
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if strings.ContainsAny(m, " \t\r\n") {
			return Add{}, fmt.Errorf("%w: model pattern %q carries a space", ErrInvalid, m)
		}
		a.Models = append(a.Models, m)
	}
	return a, nil
}

// Apply writes the add into the [proxy] tables: upstreams gains the lane,
// models (allocated when nil) its list when it has one. agent is
// [proxy.agent_upstreams], whose ids an app lane may not take.
func (a Add) Apply(upstreams, agent map[string]string, models *map[string][]string) error {
	if _, ok := upstreams[a.ID]; ok {
		return ErrExists
	}
	if _, ok := agent[a.ID]; ok {
		return ErrAgentLane
	}
	upstreams[a.ID] = a.Upstream
	if len(a.Models) > 0 {
		if *models == nil {
			*models = map[string][]string{}
		}
		(*models)[a.ID] = append([]string(nil), a.Models...)
	}
	return nil
}

// Remove deletes a lane and its own model list from the [proxy] tables.
func Remove(id string, upstreams map[string]string, autoDefault string, models map[string][]string) error {
	if _, ok := upstreams[id]; !ok {
		return ErrNotFound
	}
	if autoDefault == id {
		return ErrAutoDefault
	}
	delete(upstreams, id)
	delete(models, id)
	return nil
}
