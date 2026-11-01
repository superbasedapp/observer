package web

import (
	"net/http"
	"os"
	"path/filepath"
)

const base = "/srv/files"

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: go.path-traversal-request
	f, _ := os.Open(filepath.Join(base, name))
	// ruleid: go.path-traversal-request
	http.ServeFile(w, r, base+"/"+r.FormValue("p"))
	// ruleid: go.path-traversal-request
	_ = os.Remove(r.PathValue("id"))
	// ok: go.path-traversal-request
	g, _ := os.Open(filepath.Join(base, filepath.Base(name)))
	// ok: go.path-traversal-request
	h, _ := os.Open(filepath.Join(base, "index.html"))
	_, _, _ = f, g, h
}
