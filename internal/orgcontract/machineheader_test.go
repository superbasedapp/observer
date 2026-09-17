package orgcontract

import (
	"net/http"
	"strings"
	"testing"
)

// TestHeaderMachineIdentityIsInTheSBOFamilyAndCanonical pins the NAME, because
// both ends hard-code it: the node sets it, the server reads it, and a rename
// on one side alone degrades silently (the server simply never sees a hint and
// falls back), which is the one failure mode a header like this cannot make
// loud.
func TestHeaderMachineIdentityIsInTheSBOFamilyAndCanonical(t *testing.T) {
	if HeaderMachineIdentity != "X-SBO-Machine" {
		t.Fatalf("HeaderMachineIdentity = %q; renaming it silently disables the rail on one side", HeaderMachineIdentity)
	}
	if !strings.HasPrefix(HeaderMachineIdentity, "X-SBO-") {
		t.Errorf("%q is outside the X-SBO-* family (see HeaderAgentKeyFingerprint)", HeaderMachineIdentity)
	}
	// The spelling is the SCREAMING one the X-SBO family already uses, which is
	// NOT Go's canonical MIME form ("X-Sbo-Machine"). That is fine and is
	// asserted rather than assumed: net/http canonicalises on both Set and Get,
	// so the constant round-trips through an http.Header unchanged, and HTTP
	// field names are case-insensitive on the wire in any case.
	h := http.Header{}
	h.Set(HeaderMachineIdentity, "m-devbox")
	if got := h.Get(HeaderMachineIdentity); got != "m-devbox" {
		t.Errorf("Set/Get through %q did not round-trip (got %q)", HeaderMachineIdentity, got)
	}
	if got := h.Get(strings.ToLower(HeaderMachineIdentity)); got != "m-devbox" {
		t.Errorf("a lower-cased read of %q missed the value (got %q)", HeaderMachineIdentity, got)
	}
}

// TestSanitizeMachineHeader is the shape gate both ends share. It is a SHAPE
// check only: whether a candidate names a machine the caller owns is the
// server's question, answered against that caller's own inventory, and nothing
// here may be read as authorising anything.
func TestSanitizeMachineHeader(t *testing.T) {
	const hex64 = "3f2a1b0c9d8e7f60514233445566778899aabbccddeeff00112233445566778a"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "a real machine identity (64 hex chars)", in: hex64, want: hex64},
		{name: "a short opaque id", in: "m-devbox", want: "m-devbox"},
		{name: "exactly at the cap", in: strings.Repeat("a", machineHeaderMaxLen), want: strings.Repeat("a", machineHeaderMaxLen)},
		{name: "absent", in: "", want: ""},
		{name: "one byte over the cap", in: strings.Repeat("a", machineHeaderMaxLen+1), want: ""},
		{name: "a space is not printable-non-space ASCII", in: "m devbox", want: ""},
		{name: "leading/trailing blanks are not silently trimmed into a match", in: " " + hex64, want: ""},
		{name: "a tab", in: "m\tdevbox", want: ""},
		{name: "a newline (header smuggling shape)", in: "m-devbox\r\nX-Other: 1", want: ""},
		{name: "a NUL", in: "m-devbox\x00", want: ""},
		{name: "non-ASCII", in: "m-devbøx", want: ""},
		{name: "DEL", in: "m-devbox\x7f", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SanitizeMachineHeader(tc.in); got != tc.want {
				t.Fatalf("SanitizeMachineHeader(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
