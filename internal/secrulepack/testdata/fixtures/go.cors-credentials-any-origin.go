package web

import (
	"net/http"

	"github.com/rs/cors"
)

func handlers() {
	// ruleid: go.cors-credentials-any-origin
	a := cors.New(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true})
	// ok: go.cors-credentials-any-origin
	b := cors.New(cors.Options{AllowedOrigins: []string{"https://app.example.com"}, AllowCredentials: true})
	// ok: go.cors-credentials-any-origin
	c := cors.New(cors.Options{AllowedOrigins: []string{"*"}})
	_, _, _ = a, b, c
}

func reflect(w http.ResponseWriter, r *http.Request) {
	// ruleid: go.cors-credentials-any-origin
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func reflectNoCredentials(w http.ResponseWriter, r *http.Request) {
	// ok: go.cors-credentials-any-origin
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
}
