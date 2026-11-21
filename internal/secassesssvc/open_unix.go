//go:build unix

package secassesssvc

import "syscall"

// openFlags are the flags a read of a project file the agent named is opened
// with. O_NONBLOCK keeps open(2) from blocking on a FIFO swapped in for the
// file between the Lstat and the open: nothing can cancel a blocking open, and
// the reference walk opens up to maxRefFiles paths the agent chose.
//
// There is no O_NOFOLLOW here on purpose: os.Root already opens the last path
// element with it on every unix and, on the ELOOP that returns for a link,
// resolves the link inside the root and opens its target, so the caller's flag
// is never what stops a link. A link swapped in after a check is caught by
// comparing the opened handle with what the check saw (surveyReadOpened).
const openFlags = syscall.O_RDONLY | syscall.O_NONBLOCK
