package supervisor

import (
	"os"
	"runtime"
)

// OSProbe reads the real machine: this process's environment, the file
// system, and (on Windows) the service control database.
func OSProbe() Probe {
	home, _ := os.UserHomeDir()
	return Probe{
		GOOS:    runtime.GOOS,
		HomeDir: home,
		Getenv:  os.Getenv,
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		ServiceExists: serviceExists,
	}
}
