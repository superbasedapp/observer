//go:build unix

package host

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ownLimits returns this process's CPU, data and file-size soft limits.
func ownLimits() []string {
	var out []string
	for _, r := range []struct {
		name string
		res  int
	}{{"cpu", unix.RLIMIT_CPU}, {"data", unix.RLIMIT_DATA}, {"fsize", unix.RLIMIT_FSIZE}} {
		var l unix.Rlimit
		if err := unix.Getrlimit(r.res, &l); err != nil {
			out = append(out, r.name+"=error")
			continue
		}
		out = append(out, fmt.Sprintf("%s=%d/%d", r.name, l.Cur, l.Max))
	}
	return out
}
