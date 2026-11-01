//go:build !unix && !windows

package fsatomic

import "os"

// fileOwnerUID: this platform reports no owner uid.
func fileOwnerUID(os.FileInfo) (uint32, bool) { return 0, false }
