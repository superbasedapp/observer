package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// compiledOutBody is the 404 body a handler stub answers when its component
// is compiled out of this binary (L1, modular packaging plan 4): the same
// closed component_not_installed shape the route guard answers for an
// inactive component (componentstate.NotActiveBody), with state absent and
// reason not_compiled. It does not depend on the component service being
// wired, so a stub refuses honestly in every harness.
func compiledOutBody(id string) componentstate.NotActiveBody {
	title := id
	if c, ok := components.Get(id); ok && c.Title != "" {
		title = c.Title + " (" + id + ")"
	}
	return componentstate.NotActiveBody{
		Error:     componentstate.NotActiveError,
		Component: id,
		State:     components.StateAbsent,
		Reason:    components.ReasonNotCompiled,
		Message:   fmt.Sprintf("%s is not in this build. Settings > Components lists the builds that include it.", title),
		Fields:    componentstate.NotActiveLink(id, components.StateAbsent),
	}
}

// writeCompiledOut answers 404 component_not_installed for a compiled-out
// component. Every *_omit.go handler stub in this package uses it.
func writeCompiledOut(w http.ResponseWriter, id string) {
	writeJSONStatus(w, http.StatusNotFound, compiledOutBody(id))
}
