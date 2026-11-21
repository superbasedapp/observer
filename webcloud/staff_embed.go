package webcloud

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// The staff console's SPA (managed-SaaS M6.8; lane w17/staff-console): a
// separate Vite build (vite.staff.config.ts: staff.html, base /staff/) into
// its own committed embed dir, dist-staff, verified like dist by
// scripts/verify-webcloud-dist.sh. It is served only by the staff process
// (`observer-cloud staff serve`, api.Options.StaffSPA) behind
// http.StripPrefix("/staff", ...), never by the customer portal.

//go:embed all:dist-staff
var staffDistFS embed.FS

// staffIndex is the staff build's HTML entry (Vite names it after its input).
const staffIndex = "staff.html"

// StaffHandler serves the embedded staff console SPA. An embedded file is
// served directly; a missing file under assets/ is a 404 (a stale bundle
// asking for a chunk this build does not have); every other path is a
// client-side route and gets staff.html.
func StaffHandler() http.Handler {
	sub, err := fs.Sub(staffDistFS, "dist-staff")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "webcloud: embedded dist-staff missing", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean != "" && clean != staffIndex {
			if f, err := sub.Open(clean); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(clean, "assets/") {
				http.NotFound(w, r)
				return
			}
		}
		serveStaffIndex(w, sub)
	})
}

func serveStaffIndex(w http.ResponseWriter, sub fs.FS) {
	f, err := sub.Open(staffIndex)
	if err != nil {
		http.Error(w, "webcloud: staff.html missing", http.StatusInternalServerError)
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.Copy(w, f)
}
