package web

import (
	"html"
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse(`<p>{{.}}</p>`))

func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go.xss-request-input
	page.Execute(w, template.HTML("<b>"+name+"</b>"))
	// ok: go.xss-request-input
	page.Execute(w, name)
	// ok: go.xss-request-input
	page.Execute(w, template.HTML("<b>"+html.EscapeString(name)+"</b>"))
	// ruleid: go.xss-request-input
	attr := template.HTMLAttr(`title="` + r.FormValue("title") + `"`)
	// ok: go.xss-request-input
	fixed := template.HTML("<hr>")
	_, _ = attr, fixed
}

// The program's own values, not request input.
func badge(label string) template.HTML {
	// ok: go.xss-request-input
	return template.HTML("<span class=badge>" + label + "</span>")
}
