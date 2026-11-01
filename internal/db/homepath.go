package db

import "errors"

// ErrUnexpandedHome is the named refusal for a database path that still
// starts with "~" (R-183, home_unresolved): Open never creates a folder
// literally named "~".
var ErrUnexpandedHome = errors.New("home_unresolved: the path starts with ~ and was never expanded to a home directory")

// unexpandedHomePath reports a path whose first element is "~" ("~",
// "~/x" or `~\x`; both separators on every OS, since the folder named "~"
// is wrong whichever spelling produced it).
func unexpandedHomePath(p string) bool {
	return p == "~" || (len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == '\\'))
}
