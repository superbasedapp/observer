//go:build !unix && !windows

package sandboxrelayd

import (
	"io/fs"
	"os"
)

// ownedByMe has no portable owner check off unix; the relay ships on Linux,
// WSL2 and native Windows, so a record is refused here.
func ownedByMe(fs.FileInfo) bool { return false }

// privateFile has no portable check here: every record is refused.
func privateFile(string, *os.File, fs.FileInfo) bool { return false }

// privateDir has no portable check here: every record is refused.
func privateDir(string, fs.FileInfo) bool { return false }

// oNoFollow has no portable spelling off unix.
const oNoFollow = 0

// oNonblock has no portable spelling off unix.
const oNonblock = 0

// clearNonblock has nothing to clear off unix.
func clearNonblock(*os.File) {}
