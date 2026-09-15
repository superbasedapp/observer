package inspectionbroker

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDefaultSocketPath(t *testing.T) {
	t.Parallel()
	if got, want := DefaultSocketPath(1000), "/run/observer-node-inspection/1000.sock"; got != want {
		t.Fatalf("DefaultSocketPath() = %q, want %q", got, want)
	}
}

func TestReadFrameRejectsMalformedAndOversizedInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing newline", raw: `{"version":1}`},
		{name: "malformed JSON", raw: "{not-json}\n"},
		{name: "unknown field", raw: `{"version":1,"kind":"inspect","extra":true}` + "\n"},
		{name: "trailing value", raw: `{"version":1} {}` + "\n"},
		{name: "oversized", raw: strings.Repeat("x", MaxMessageBytes) + "\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request inspectRequest
			if err := readFrame(strings.NewReader(test.raw), &request); !errors.Is(err, ErrProtocol) {
				t.Fatalf("readFrame() error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestWriteFrameRejectsOversizedOutput(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := writeFrame(&output, map[string]string{"value": strings.Repeat("x", MaxMessageBytes)}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("writeFrame() error = %v, want ErrProtocol", err)
	}
	if output.Len() != 0 {
		t.Fatalf("writeFrame() wrote %d bytes for oversized output", output.Len())
	}
}

func TestValidRequestRequiresCryptographicNonceShapeAndBirth(t *testing.T) {
	t.Parallel()
	request := inspectRequest{
		Version: wireVersion, Kind: kindInspect, PID: 123, StartTicks: 456,
		BootID: "boot-1", Nonce: strings.Repeat("a", nonceBytes*2),
	}
	if !validRequest(request) {
		t.Fatal("complete request rejected")
	}
	for _, mutate := range []func(*inspectRequest){
		func(r *inspectRequest) { r.PID = 1 },
		func(r *inspectRequest) { r.StartTicks = 0 },
		func(r *inspectRequest) { r.BootID = " boot" },
		func(r *inspectRequest) { r.Nonce = strings.Repeat("A", nonceBytes*2) },
		func(r *inspectRequest) { r.Nonce = strings.Repeat("g", nonceBytes*2) },
	} {
		invalid := request
		mutate(&invalid)
		if validRequest(invalid) {
			t.Fatalf("invalid request accepted: %+v", invalid)
		}
	}
}
