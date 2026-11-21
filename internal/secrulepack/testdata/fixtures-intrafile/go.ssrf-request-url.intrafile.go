package web

import (
	"net/http"
	"net/url"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that fetches it.
func fetchURL(target string) (*http.Response, error) {
	// ruleid: go.ssrf-request-url
	return http.Get(target)
}

func preview(w http.ResponseWriter, r *http.Request) {
	_, _ = fetchURL(r.URL.Query().Get("url"))
}

func requestedURL(r *http.Request) string {
	return r.FormValue("callback")
}

func callback(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.ssrf-request-url
	_, _ = http.Get(requestedURL(r))
}

// The sanitizer sits in the helper: the value is query-escaped before the
// caller fetches it.
func escaped(value string) string {
	return url.QueryEscape(value)
}

func previewEscaped(w http.ResponseWriter, r *http.Request) {
	// ok: go.ssrf-request-url
	_, _ = http.Get(escaped(r.URL.Query().Get("url")))
}
