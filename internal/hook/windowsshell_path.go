package hook

import "sync"

// PersistentWindowsPATH is the production Options.WindowsPATH: the Windows
// PATH a newly launched program inherits (the machine PATH, then the user
// PATH), read once per process. On a Windows observer it comes from the
// registry; from WSL through powershell.exe over interop (the antigravity
// adapter's precedent), converted to /mnt/<drive>/ form. ok=false when it
// cannot be read (not Windows and not WSL, interop off, a timeout).
func PersistentWindowsPATH() (string, bool) {
	persistentPATHOnce.Do(func() {
		persistentPATH, persistentPATHOK = readPersistentWindowsPATH()
	})
	return persistentPATH, persistentPATHOK
}

var (
	persistentPATHOnce sync.Once
	persistentPATH     string
	persistentPATHOK   bool
)
