//go:build !unix

package main

import "io/fs"

// sdkHeldFileForeignOwner cannot tell the owner here: on Windows the SDKs
// compare the owner SID, which `observer sdk status` does not read, so the
// report leaves that rule to the SDK.
func sdkHeldFileForeignOwner(fs.FileInfo) bool { return false }
