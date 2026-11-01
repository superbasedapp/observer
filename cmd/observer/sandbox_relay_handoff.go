//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"strconv"
)

// parseRelayChannelID reads the channel id a relay child's environment
// names (a descriptor on unix, a handle value on Windows): a positive
// decimal number with no sign, space or leading zero, nothing else. The
// per-OS relayChannelFile then checks what the number must be (fd 3 on
// unix, an open pipe handle on Windows).
func parseRelayChannelID(s string) (uint64, error) {
	if s == "" || len(s) > 20 || s[0] == '0' {
		return 0, fmt.Errorf("relay channel id %q", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("relay channel id %q", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("relay channel id %q", s)
	}
	return n, nil
}
