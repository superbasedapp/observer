//go:build !unix

package listenhandover

import "os"

// Supported is false: without execve there is no re-exec to pass a socket
// across. A Windows daemon's restart keeps its own refusal (quit it and
// start it again between AI turns).
func Supported() bool { return false }

func keepOnExec(*os.File) (int, error) { return 0, ErrUnsupported }

// inheritedFile never adopts a descriptor here.
func inheritedFile(int) *os.File { return nil }
