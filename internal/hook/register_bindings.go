package hook

import "github.com/marmutapp/superbased-observer/internal/integration"

// registeredEvents returns the native events the registry row for tool
// binds as Registered, in binding order, de-duplicated: the event list a
// per-format writer registers (hook-parity audit section 5.4: writers take
// their event list from the bindings, not from a per-vendor slice). nil for
// an unknown tool or a row that registers nothing.
func registeredEvents(tool string) []string {
	c, ok := integration.For(tool)
	if !ok {
		return nil
	}
	return c.Hook.RegisteredEvents()
}

// registeredEventsFor is registeredEvents(tool) plus the events of the
// row's RegisterWhen bindings whose component Options.Selected selects
// (integration.HookSpec.RegisteredEventsWith), or fallback when the row
// declares none.
func (r *Registry) registeredEventsFor(tool string, fallback ...string) []string {
	c, ok := integration.For(tool)
	if !ok {
		return fallback
	}
	if ev := c.Hook.RegisteredEventsWith(r.opts.Selected); len(ev) > 0 {
		return ev
	}
	return fallback
}

// allEventsFor is every event Observer may have written for tool: the
// static ones and every RegisterWhen event whatever is selected (what an
// unregister removes).
func allEventsFor(tool string, fallback ...string) []string {
	c, ok := integration.For(tool)
	if !ok {
		return fallback
	}
	if ev := c.Hook.RegisteredEventsWith(func(string) bool { return true }); len(ev) > 0 {
		return ev
	}
	return fallback
}

// optInEventsOff is the row's RegisterWhen events whose component is not
// selected: a writer removes Observer's entry for each. None while
// Options.Selected is nil (no selection given: opt-in entries stay).
func (r *Registry) optInEventsOff(tool string) []string {
	if r.opts.Selected == nil {
		return nil
	}
	c, ok := integration.For(tool)
	if !ok {
		return nil
	}
	return c.Hook.OptInEvents(r.opts.Selected)
}

// eventsOr returns registeredEvents(tool), or fallback when the registry
// declares none (a writer is never left with an empty list by a registry
// row that has not grown bindings).
func eventsOr(tool string, fallback ...string) []string {
	if ev := registeredEvents(tool); len(ev) > 0 {
		return ev
	}
	return fallback
}
