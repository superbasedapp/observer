// Package webcloud embeds the app.superbased.app portal SPA (CI-P5b) so
// cmd/observer-cloud can serve it. The caller mounts Handler() behind
// http.StripPrefix("/portal", ...), so requests arrive already stripped of the
// /portal prefix and this handler serves from the dist root.
package webcloud

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded cloud portal SPA.
// A direct hit on a fingerprinted asset (under /assets/*) is served by the file
// server; every other path is a client-side route and falls back to index.html
// so React Router can render it. The handler is mounted behind
// http.StripPrefix("/portal", ...) by the caller, so paths arrive already
// stripped of the /portal prefix and are served from the dist root.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "webcloud: embedded dist missing", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			serveIndex(w, sub)
			return
		}
		if f, err := sub.Open(clean); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, sub)
	})
}

func serveIndex(w http.ResponseWriter, sub fs.FS) {
	f, err := sub.Open("index.html")
	if err != nil {
		http.Error(w, "webcloud: index.html missing", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.Copy(w, f)
}
