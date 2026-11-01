package sandboxvm

import (
	"errors"
	"fmt"
	"io"
	"strconv"
)

// handshake.go is Cloud Hypervisor's hybrid vsock exchange, the host side
// (firecracker's protocol, which Cloud Hypervisor implements): the host
// connects to the VMM's vsock unix socket and writes `CONNECT <port>\n`;
// the VMM answers `OK <hostport>\n` once the guest accepted on that port,
// hostport being the ephemeral host-side port it allocated (2^30 upward).
// A refused port or an unknown verb closes the socket with zero bytes; the
// verb is case-insensitive; the VMM waits forever for a request without a
// newline. So the reader treats EOF before the newline as refused, reads at
// most maxAnswer bytes one at a time (never past the newline, so the relay
// mux's first bytes stay unread), and the caller applies a read deadline.

// maxAnswer caps the answer line: "OK 4294967295\n" is 14 bytes.
const maxAnswer = 32

// HostPortMin is the lowest host-side port the VMM allocates.
const HostPortMin = 1 << 30

// Errors.
var (
	// ErrVsockRefused: the VMM closed the socket before answering (no
	// listener on the port, or a request it does not understand).
	ErrVsockRefused = errors.New("sandboxvm: the VMM refused the vsock connection")
	// ErrVsockMalformed: the VMM answered something other than OK <port>.
	ErrVsockMalformed = errors.New("sandboxvm: the VMM's vsock answer is malformed")
)

// ConnectRequest is the request line for guest port.
func ConnectRequest(port uint32) ([]byte, error) {
	if port == 0 {
		return nil, errors.New("sandboxvm: vsock port 0")
	}
	return []byte("CONNECT " + strconv.FormatUint(uint64(port), 10) + "\n"), nil
}

// ReadConnectAnswer reads the VMM's answer line from r one byte at a time
// and returns the host-side port.
func ReadConnectAnswer(r io.Reader) (uint32, error) {
	var line []byte
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return ParseConnectAnswer(line)
			}
			line = append(line, b[0])
			if len(line) >= maxAnswer {
				return 0, fmt.Errorf("%w: no newline within %d bytes", ErrVsockMalformed, maxAnswer)
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, ErrVsockRefused
			}
			return 0, fmt.Errorf("%w: %w", ErrVsockRefused, err)
		}
	}
}

// ParseConnectAnswer parses one answer line without its newline.
func ParseConnectAnswer(line []byte) (uint32, error) {
	if len(line) < 4 || line[0] != 'O' || line[1] != 'K' || line[2] != ' ' {
		return 0, ErrVsockMalformed
	}
	digits := line[3:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, ErrVsockMalformed
		}
	}
	if len(digits) > 10 || (len(digits) > 1 && digits[0] == '0') {
		return 0, ErrVsockMalformed
	}
	n, err := strconv.ParseUint(string(digits), 10, 32)
	if err != nil || n < HostPortMin {
		return 0, ErrVsockMalformed
	}
	return uint32(n), nil
}
