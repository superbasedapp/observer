//go:build !windows

package sandboxhcs

// NewSystemLoader off Windows always fails its load.
func NewSystemLoader() *Loader { return NewLoader(nil) }
