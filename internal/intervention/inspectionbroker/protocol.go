package inspectionbroker

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

const (
	// MaxMessageBytes is the maximum size of one newline-terminated protocol
	// frame. Each connection carries exactly one request and one response.
	MaxMessageBytes = 4096

	wireVersion = 1
	nonceBytes  = 32
	maxBootID   = 128
)

var (
	// ErrUnavailable reports that the broker could not be reached or its local
	// socket path did not meet the root-ownership requirements.
	ErrUnavailable = errors.New("inspection broker unavailable")
	// ErrUnauthorized reports that the server refused the authenticated peer.
	ErrUnauthorized = errors.New("inspection broker peer unauthorized")
	// ErrInvalidRequest reports invalid caller-supplied process birth fields.
	ErrInvalidRequest = errors.New("inspection broker invalid request")
	// ErrIdentityMismatch reports that the target identity changed or did not
	// equal the requested process birth and configured operating-system user.
	ErrIdentityMismatch = errors.New("inspection broker identity mismatch")
	// ErrInspectionUnavailable reports that the privileged process identity
	// could not be read completely.
	ErrInspectionUnavailable = errors.New("inspection broker inspection unavailable")
	// ErrProtocol reports a malformed, oversized, stale or otherwise invalid
	// protocol response.
	ErrProtocol = errors.New("inspection broker protocol error")
	// ErrTimeout reports that a bounded broker operation reached its deadline.
	ErrTimeout = errors.New("inspection broker timeout")
	// ErrCanceled reports cancellation of a broker operation.
	ErrCanceled = errors.New("inspection broker canceled")
)

const (
	kindInspect = "inspect"
	kindResult  = "result"

	codeUnauthorized          = "unauthorized"
	codeInvalidRequest        = "invalid_request"
	codeIdentityMismatch      = "identity_mismatch"
	codeInspectionUnavailable = "inspection_unavailable"
)

type inspectRequest struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	PID        int    `json:"pid"`
	StartTicks int64  `json:"start_ticks"`
	BootID     string `json:"boot_id"`
	Nonce      string `json:"nonce"`
}

type inspectResponse struct {
	Version  int                    `json:"version"`
	Kind     string                 `json:"kind"`
	Nonce    string                 `json:"nonce"`
	Identity *intervention.Identity `json:"identity,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// Peer is the kernel-authenticated Unix-socket peer presented to a server
// authorization callback.
type Peer struct {
	PID int
	UID int
	GID int
}

// DefaultSocketPath returns the fixed root-runtime socket path for targetUID.
// Callers must reject negative UIDs before creating or dialing it.
func DefaultSocketPath(targetUID int) string {
	return filepath.Join("/run/observer-node-inspection", strconv.Itoa(targetUID)+".sock")
}

func validRequest(request inspectRequest) bool {
	if request.Version != wireVersion || request.Kind != kindInspect ||
		request.PID <= 1 || request.StartTicks <= 0 || !validBootID(request.BootID) {
		return false
	}
	raw, err := hex.DecodeString(request.Nonce)
	return err == nil && len(raw) == nonceBytes && strings.ToLower(request.Nonce) == request.Nonce
}

func validBootID(bootID string) bool {
	if bootID == "" || len(bootID) > maxBootID || strings.TrimSpace(bootID) != bootID {
		return false
	}
	for _, r := range bootID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func validIdentity(identity intervention.Identity) bool {
	return validBootID(identity.BootID) && identity.PID > 1 &&
		identity.StartTicks > 0 && identity.UID >= 0 &&
		identity.Executable.Device != 0 && identity.Executable.Inode != 0
}

func responseError(code string) error {
	switch code {
	case codeUnauthorized:
		return ErrUnauthorized
	case codeInvalidRequest:
		return ErrInvalidRequest
	case codeIdentityMismatch:
		return ErrIdentityMismatch
	case codeInspectionUnavailable:
		return ErrInspectionUnavailable
	default:
		return ErrProtocol
	}
}

func writeFrame(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrProtocol
	}
	raw = append(raw, '\n')
	if len(raw) > MaxMessageBytes {
		return ErrProtocol
	}
	for len(raw) > 0 {
		written, writeErr := writer.Write(raw)
		if writeErr != nil || written <= 0 || written > len(raw) {
			return ErrUnavailable
		}
		raw = raw[written:]
	}
	return nil
}

func readFrame(reader io.Reader, value any) error {
	buffered := bufio.NewReaderSize(reader, MaxMessageBytes)
	raw, err := buffered.ReadSlice('\n')
	if err != nil {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
			return ErrTimeout
		}
		return ErrProtocol
	}
	if len(raw) == 0 || len(raw) > MaxMessageBytes || raw[len(raw)-1] != '\n' {
		return ErrProtocol
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrProtocol
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrProtocol
	}
	return nil
}
