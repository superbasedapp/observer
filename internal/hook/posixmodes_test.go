package hook

import (
	"runtime"
	"testing"
)

// setTestHome points the home directory at dir for this test on every OS:
// HOME, and on Windows USERPROFILE, which is what os.UserHomeDir reads on Windows. A
// test that set HOME alone shared the real profile's ~/.observer there, so
// rows other tests wrote (the debug and forensic dumps) showed up in its
// count (Windows 11 Pro live run, PT-02).
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
}

// posixModes reports whether this OS keeps POSIX permission bits. On
// Windows os.Stat reports 0666 for any writable file and the hook writers
// set no DACL on a vendor's own config file, so a test that pins a kept
// 0600 or 0640 mode skips that one assertion there (Windows 11 Pro live
// run, PT-02 group "file modes").
var posixModes = runtime.GOOS != "windows"
