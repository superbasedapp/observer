package web

import (
	"context"
	"net/http"
	"net/url"
)

func preview(w http.ResponseWriter, r *http.Request, client *http.Client) {
	target := r.URL.Query().Get("url")
	// ruleid: go.ssrf-request-url
	a, _ := http.Get(target)
	// ruleid: go.ssrf-request-url
	b, _ := http.NewRequestWithContext(context.Background(), "GET", r.FormValue("callback"), nil)
	// ruleid: go.ssrf-request-url
	c, _ := client.Get("http://" + r.Form.Get("host") + "/status")
	// ok: go.ssrf-request-url
	d, _ := http.Get("https://api.example.com/search?q=" + url.QueryEscape(target))
	// ok: go.ssrf-request-url
	e, _ := http.Get("https://api.example.com/users/" + r.PathValue("id"))
	_, _, _, _, _ = a, b, c, d, e
}

// The false-positive shape of the 1.1.0 rule: a reverse proxy forwarding
// the query string to its fixed upstream.
func forward(r *http.Request, upstream *url.URL) {
	out := *upstream
	out.RawQuery = r.URL.RawQuery
	// ok: go.ssrf-request-url
	_, _ = http.NewRequestWithContext(r.Context(), r.Method, out.String(), r.Body)
}
