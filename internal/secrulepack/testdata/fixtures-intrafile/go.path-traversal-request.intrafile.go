package web

import (
	"net/http"
	"os"
	"path/filepath"
)

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that opens it.
func openNamed(name string) (*os.File, error) {
	// ruleid: go.path-traversal-request
	return os.Open(name)
}

func download(w http.ResponseWriter, r *http.Request) {
	f, _ := openNamed(r.FormValue("name"))
	_ = f
}

func requestedPath(r *http.Request) string {
	return r.URL.Query().Get("path")
}

func remove(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.path-traversal-request
	_ = os.Remove(requestedPath(r))
}

// The sanitizer sits in the helper: the name is reduced to its base name
// before the caller opens it.
func baseName(name string) string {
	return filepath.Base(name)
}

func downloadBase(w http.ResponseWriter, r *http.Request) {
	// ok: go.path-traversal-request
	f, _ := os.Open(baseName(r.FormValue("name")))
	_ = f
}
