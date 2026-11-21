package sandboxsetup

import "runtime"

// pins is the compiled download pin table. pins.go (lane download) fills it
// from its own init, so this file never names a version or a digest.
var pins []Pin

// pinFor returns the pin for id on the build's own OS and architecture.
func pinFor(id string) (Pin, bool) {
	return pinMatching(id, runtime.GOOS, runtime.GOARCH)
}

// pinMatching returns the pin for id on goos and goarch ("" goarch means the
// build's own).
func pinMatching(id, goos, goarch string) (Pin, bool) {
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	for _, p := range pins {
		if p.ID == id && p.GOOS == goos && p.GOARCH == goarch {
			return p, true
		}
	}
	return Pin{}, false
}

// PinFor is pinFor for the cmd-side runner: the pin a pinned_download step of
// this build would fetch.
func PinFor(id string) (Pin, bool) { return pinFor(id) }
