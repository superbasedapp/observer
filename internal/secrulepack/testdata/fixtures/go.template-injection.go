package web

import (
	"html/template"
	"net/http"
	"net/url"
)

func render(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.template-injection
	t, _ := template.New("page").Parse(r.FormValue("tpl"))
	// ruleid: go.template-injection
	u := template.Must(template.New("x").Parse("<p>" + r.URL.Query().Get("greeting") + "</p>"))
	// ok: go.template-injection
	s := template.Must(template.New("x").Parse("<p>{{.}}</p>"))
	// ok: go.template-injection
	link, _ := url.Parse(r.FormValue("next"))
	_ = t.Execute(w, nil)
	_ = u.Execute(w, nil)
	_ = s.Execute(w, r.FormValue("greeting"))
	_ = link
}
