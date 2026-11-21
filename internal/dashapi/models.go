package dashapi

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ModelOffered reports whether model is one the New Terminal model picker
// offers for tool: the tool's recent history (recentModels) plus its
// registry Known list, for a terminal-launchable tool with a model
// capability. It is the ONE membership rule the dashboard's launch route
// and `observer launch --model` both apply (the dashboard drops an
// unoffered model, the CLI refuses it). The dashboard's picker builds the
// same set with counts (modelSuggestionsFor), pinned equal by
// TestModelOfferedMatchesThePicker. A nil recentModels offers nothing, as
// the picker does; a history read error leaves the Known list.
func ModelOffered(ctx context.Context, recentModels func(context.Context, string) ([]store.RecentToolModel, error), tool, model string) bool {
	if recentModels == nil || model == "" {
		return false
	}
	c, ok := integration.For(tool)
	if !ok || !integration.TerminalLaunchable(c) || c.Model.Kind == integration.ModelNone {
		return false
	}
	if history, err := recentModels(ctx, tool); err == nil {
		for _, h := range history {
			if h.Model == model {
				return true
			}
		}
	}
	for _, m := range c.Model.Known {
		if m == model {
			return true
		}
	}
	return false
}
