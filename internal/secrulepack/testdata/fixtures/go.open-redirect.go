package web

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func loginDone(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, "/items/"+r.FormValue("id"), http.StatusFound)
	// ruleid: go.open-redirect
	http.Redirect(w, r, "/"+r.FormValue("path"), http.StatusFound)
	// ok: go.open-redirect
	http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
}

func goTo(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.open-redirect
	w.Header().Set("Location", r.FormValue("to"))
	w.WriteHeader(http.StatusFound)
}

func ginDone(c *gin.Context) {
	// ruleid: go.open-redirect
	c.Redirect(http.StatusFound, c.DefaultQuery("returnTo", "/"))
}

// The program's own values, not request input.
func home(w http.ResponseWriter, r *http.Request, target string) {
	// ok: go.open-redirect
	http.Redirect(w, r, target, http.StatusFound)
}
