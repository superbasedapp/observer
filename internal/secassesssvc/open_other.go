//go:build !unix

package secassesssvc

import "os"

// openFlags are the flags a read of a project file the agent named is opened
// with. There is no FIFO to swap in on this platform, so no non-blocking flag
// exists to set.
const openFlags = os.O_RDONLY
