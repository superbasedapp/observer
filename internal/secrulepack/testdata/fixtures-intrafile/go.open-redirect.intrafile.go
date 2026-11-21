package web

import (
	"net/http"
	"net/url"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that redirects to it.
func sendTo(w http.ResponseWriter, r *http.Request, target string) {
	// ruleid: go.open-redirect
	http.Redirect(w, r, target, http.StatusFound)
}

func done(w http.ResponseWriter, r *http.Request) {
	sendTo(w, r, r.URL.Query().Get("next"))
}

func returnTarget(r *http.Request) string {
	return r.FormValue("return_to")
}

func finish(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.open-redirect
	http.Redirect(w, r, returnTarget(r), http.StatusFound)
}

// The sanitizer sits in the helper: the value is escaped before the caller
// redirects to it.
func escaped(value string) string {
	return url.PathEscape(value)
}

func bounce(w http.ResponseWriter, r *http.Request) {
	// ok: go.open-redirect
	http.Redirect(w, r, escaped(r.FormValue("next")), http.StatusFound)
}
