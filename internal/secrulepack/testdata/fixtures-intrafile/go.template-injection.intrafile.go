package web

import (
	"html/template"
	"net/http"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that parses it as a template.
func parseTemplate(source string) (*template.Template, error) {
	// ruleid: go.template-injection
	return template.New("page").Parse(source)
}

func page(w http.ResponseWriter, r *http.Request) {
	t, _ := parseTemplate(r.FormValue("tpl"))
	_ = t
}

func requestedTemplate(r *http.Request) string {
	return r.URL.Query().Get("tpl")
}

func pageReturned(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.template-injection
	t, _ := template.New("page").Parse(requestedTemplate(r))
	_ = t
}

// The helper takes the request value but returns a fixed template; nothing
// of the input becomes template source.
func fixedTemplate(requested string) string {
	return "<p>{{.Name}}</p>"
}

func pageFixed(w http.ResponseWriter, r *http.Request) {
	// ok: go.template-injection
	t, _ := template.New("page").Parse(fixedTemplate(r.FormValue("tpl")))
	_ = t
}
