//go:build !unix

package diag

import "os"

// ownedByRoot cannot tell on this platform (Windows ACLs are not inspected).
func ownedByRoot(os.FileInfo) (root, known bool) { return false, false }
