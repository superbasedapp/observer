package openshellorg

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// DeviceCodeTTL is how long a device approval stays open (section 5.3).
const DeviceCodeTTL = 10 * time.Minute

// DeviceState is a device code's state.
type DeviceState string

// The closed device-code states.
const (
	DevicePending  DeviceState = "pending"
	DeviceApproved DeviceState = "approved"
	DeviceConsumed DeviceState = "consumed"
	DeviceExpired  DeviceState = "expired"
)

// DeviceEvent is what happens to a device code.
type DeviceEvent string

// The closed device-code events.
const (
	// DeviceApprove is the signed-in member's approval on the page.
	DeviceApprove DeviceEvent = "approve"
	// DevicePoll is the node's poll.
	DevicePoll DeviceEvent = "poll"
	// DeviceExpire is time passing the expiry.
	DeviceExpire DeviceEvent = "expire"
)

// deviceRow is one row of the device-code transition table.
type deviceRow struct {
	From  DeviceState
	Event DeviceEvent
	To    DeviceState
	// Reason answers a poll or an approval that leaves the state.
	Reason Reason
}

// deviceTable is the device-code state machine, walked top-down. A pair that
// is not listed is refused with ReasonIllegalTransition.
var deviceTable = []deviceRow{
	{DevicePending, DeviceApprove, DeviceApproved, ReasonNone},
	{DevicePending, DevicePoll, DevicePending, ReasonDeviceCodePending},
	{DevicePending, DeviceExpire, DeviceExpired, ReasonDeviceCodeExpired},
	{DeviceApproved, DevicePoll, DeviceConsumed, ReasonNone},
	{DeviceApproved, DeviceExpire, DeviceExpired, ReasonDeviceCodeExpired},
	{DeviceApproved, DeviceApprove, DeviceApproved, ReasonIllegalTransition},
	{DeviceConsumed, DevicePoll, DeviceConsumed, ReasonDeviceCodeConsumed},
	{DeviceConsumed, DeviceApprove, DeviceConsumed, ReasonDeviceCodeConsumed},
	{DeviceExpired, DevicePoll, DeviceExpired, ReasonDeviceCodeExpired},
	{DeviceExpired, DeviceApprove, DeviceExpired, ReasonDeviceCodeExpired},
}

// DeviceStep answers the next state and the reason for event on a code in
// state from, created at expires-minus-TTL. A code past its expiry behaves
// as expired whatever its stored state, unless it was already consumed.
func DeviceStep(from DeviceState, ev DeviceEvent, expiresAt, now time.Time) (DeviceState, Reason) {
	if from != DeviceConsumed && from != DeviceExpired && !now.Before(expiresAt) {
		from = DeviceExpired
	}
	for _, r := range deviceTable {
		if r.From == from && r.Event == ev {
			return r.To, r.Reason
		}
	}
	return from, ReasonIllegalTransition
}

// userCodeAlphabet has no vowels and no look-alike characters, so a user
// code never spells a word and is easy to type.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLen is the number of letters in a user code (shown as XXXX-XXXX).
const UserCodeLen = 8

// NewUserCode reads a user code from rand, formatted XXXX-XXXX.
func NewUserCode(rand io.Reader) (string, error) {
	b := make([]byte, UserCodeLen)
	if _, err := io.ReadFull(rand, b); err != nil {
		return "", fmt.Errorf("openshellorg.NewUserCode: %w", err)
	}
	out := make([]byte, 0, UserCodeLen+1)
	for i, c := range b {
		if i == UserCodeLen/2 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(c)%len(userCodeAlphabet)])
	}
	return string(out), nil
}

// NormalizeUserCode folds a typed user code to its stored form: upper case,
// separators and spaces removed, then re-split XXXX-XXXX. It answers "" for a
// value that cannot be a user code.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return ""
		}
	}
	v := b.String()
	if len(v) != UserCodeLen {
		return ""
	}
	return v[:UserCodeLen/2] + "-" + v[UserCodeLen/2:]
}
