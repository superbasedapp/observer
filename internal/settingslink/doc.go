// Package settingslink is the ONE owner of the local dashboard's
// "turn something on" deep links: when an API answer means a setting or a
// component must be switched on before the request can work, the body
// carries the in-app path that opens the exact place to change it, the
// place's plain name, and (where one exists) the CLI command that does the
// same.
//
// A second closed table names places in the TEAM dashboard (the org
// server's own dashboard) for settings only the organization's admins can
// change: the node links there (or names the place in words) and never
// offers a toggle of its own.
//
// The places are a closed table (Place -> path, label). A component's link
// is built from the one Components page path with the component focused.
// Every error site resolves its link through this package, never by
// string-building a path at the site, so the SPA's routes are spelled once on
// the Go side.
//
// Pure: no I/O, no SQL, no HTTP, no observer-internal imports.
package settingslink
