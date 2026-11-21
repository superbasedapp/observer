package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// start_signin.go is `observer start`'s sign-in nudge (Getting started v2):
// signing in is the recommended next step on every local surface, never a
// gate. Two lines, only when this machine is signed out and not connected.

// startSignInHint returns the nudge lines: none when signed in, connected,
// or in a build with no SuperBased sign-in (identity unknown). dashboard says
// whether a dashboard is being served to sign in from.
func startSignInHint(id frontdoor.Identity, connected, dashboard bool) []string {
	if id != frontdoor.IdentitySignedOut || connected {
		return nil
	}
	next := "  next: run `observer connect` to sign in"
	if dashboard {
		next = "  next: sign in on the dashboard, or run `observer connect`"
	}
	return []string{next, "  data stays on this machine until you connect it"}
}

// printStartSignInHint prints startSignInHint for this machine. db is the
// daemon's handle (nil reads as not connected).
func printStartSignInHint(ctx context.Context, w io.Writer, configPath string, db *sql.DB, dashboard bool) {
	connected := false
	if db != nil {
		if enr, err := store.New(db).LoadEnrolment(ctx); err == nil && enr != nil {
			connected = true
		}
	}
	for _, l := range startSignInHint(connectIdentityState(configPath), connected, dashboard) {
		fmt.Fprintln(w, l)
	}
}
