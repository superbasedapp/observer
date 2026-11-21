package web

import (
	"html"
	"html/template"
	"net/http"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that marks it trusted HTML.
func asHeading(text string) template.HTML {
	// ruleid: go.xss-request-input
	return template.HTML("<h1>" + text + "</h1>")
}

func heading(w http.ResponseWriter, r *http.Request) {
	_ = asHeading(r.FormValue("title"))
}

func requestedNote(r *http.Request) string {
	return r.URL.Query().Get("note")
}

func note(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.xss-request-input
	_ = template.HTML("<p>" + requestedNote(r) + "</p>")
}

// The sanitizer sits in the helper: the value is escaped before the caller
// marks it trusted.
func escaped(value string) string {
	return html.EscapeString(value)
}

func comment(w http.ResponseWriter, r *http.Request) {
	// ok: go.xss-request-input
	_ = template.HTML("<p>" + escaped(r.FormValue("comment")) + "</p>")
}
