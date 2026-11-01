//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strconv"
	"testing"
)

// TestParseRelayChannelID is the relay hand-off's id rule on every OS
// (SBX-P6 audit item 8): what relayHandOff writes reads back; anything else
// (empty, zero, signed, padded, spaced, hex, overflowing) is refused.
func TestParseRelayChannelID(t *testing.T) {
	for _, v := range []uint64{3, 4, 1240, 1 << 40} {
		got, err := parseRelayChannelID(strconv.FormatUint(v, 10))
		if err != nil || got != v {
			t.Errorf("%d: %d %v", v, got, err)
		}
	}
	for _, bad := range []string{"", "0", "03", "+3", "-3", " 3", "3 ", "0x10", "3a", "99999999999999999999", "18446744073709551616"} {
		if _, err := parseRelayChannelID(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
