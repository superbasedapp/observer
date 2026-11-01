//go:build !unix

package hostfile

import "errors"

func mkfifo(string) error { return errors.New("FIFOs are unix only") }
