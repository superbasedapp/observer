//go:build linux

package inspectionbroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

const (
	defaultTimeout = 2 * time.Second
	maximumTimeout = 10 * time.Second
)

// Client performs one authenticated, bounded identity request per Unix-socket
// connection. TargetUID is the only process principal it will accept.
type Client struct {
	SocketPath string
	TargetUID  int
	Timeout    time.Duration

	testRootUID         int
	testRootUIDSet      bool
	testPathOwner       func(int) bool
	testSkipParentTrust bool
}

type socketIdentity struct {
	device uint64
	inode  uint64
}

// Inspect asks the privileged broker for the exact nonsensitive identity of a
// process whose PID and birth fields were already observed locally.
func (client Client) Inspect(ctx context.Context, pid int, startTicks int64, bootID string) (intervention.Identity, error) {
	if ctx == nil || client.TargetUID < 0 || client.SocketPath == "" ||
		pid <= 1 || startTicks <= 0 || !validBootID(bootID) {
		return intervention.Identity{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return intervention.Identity{}, contextError(err)
	}

	nonceRaw := make([]byte, nonceBytes)
	if _, err := rand.Read(nonceRaw); err != nil {
		return intervention.Identity{}, ErrUnavailable
	}
	nonce := hex.EncodeToString(nonceRaw)
	request := inspectRequest{
		Version: wireVersion, Kind: kindInspect, PID: pid,
		StartTicks: startTicks, BootID: bootID, Nonce: nonce,
	}

	trustedSocket, err := client.validateSocketPath()
	if err != nil {
		return intervention.Identity{}, ErrUnavailable
	}
	deadline := boundedDeadline(ctx, client.Timeout)
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", client.SocketPath)
	if err != nil {
		return intervention.Identity{}, classifyClientError(ctx, err)
	}
	defer func() { _ = connection.Close() }()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return intervention.Identity{}, ErrUnavailable
	}
	if err := unixConnection.SetDeadline(deadline); err != nil {
		return intervention.Identity{}, ErrUnavailable
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = unixConnection.SetDeadline(time.Now()) })
	defer stopCancel()

	peer, err := unixPeer(unixConnection)
	if err != nil || peer.UID != client.trustedRootUID() {
		return intervention.Identity{}, ErrUnavailable
	}
	currentSocket, err := client.validateSocketPath()
	if err != nil || currentSocket != trustedSocket {
		return intervention.Identity{}, ErrUnavailable
	}
	if err := writeFrame(unixConnection, request); err != nil {
		return intervention.Identity{}, classifyClientError(ctx, err)
	}
	var response inspectResponse
	if err := readFrame(unixConnection, &response); err != nil {
		return intervention.Identity{}, classifyClientError(ctx, err)
	}
	if response.Version != wireVersion || response.Kind != kindResult || response.Nonce != nonce {
		return intervention.Identity{}, ErrProtocol
	}
	if response.Error != "" {
		if response.Identity != nil {
			return intervention.Identity{}, ErrProtocol
		}
		return intervention.Identity{}, responseError(response.Error)
	}
	if response.Identity == nil || !validIdentity(*response.Identity) {
		return intervention.Identity{}, ErrProtocol
	}
	identity := *response.Identity
	if identity.PID != pid || identity.StartTicks != startTicks ||
		identity.BootID != bootID || identity.UID != client.TargetUID {
		return intervention.Identity{}, ErrIdentityMismatch
	}
	return identity, nil
}

func (client Client) trustedRootUID() int {
	if client.testRootUIDSet {
		return client.testRootUID
	}
	return 0
}

func (client Client) validateSocketPath() (socketIdentity, error) {
	path := client.SocketPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return socketIdentity{}, ErrUnavailable
	}
	rootUID := client.trustedRootUID()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm()&0o002 != 0 || fileUID(info) != rootUID {
		return socketIdentity{}, ErrUnavailable
	}
	identity, ok := fileIdentity(info)
	if !ok {
		return socketIdentity{}, ErrUnavailable
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		parentInfo, statErr := os.Lstat(parent)
		owner := fileUID(parentInfo)
		if statErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			return socketIdentity{}, ErrUnavailable
		}
		if !client.testSkipParentTrust && (parentInfo.Mode().Perm()&0o022 != 0 || !client.trustedPathOwner(owner)) {
			return socketIdentity{}, ErrUnavailable
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	return identity, nil
}

func (client Client) trustedPathOwner(uid int) bool {
	if client.testPathOwner != nil {
		return client.testPathOwner(uid)
	}
	return uid == 0
}

func fileUID(info os.FileInfo) int {
	if info == nil {
		return -1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func fileIdentity(info os.FileInfo) (socketIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketIdentity{}, false
	}
	return socketIdentity{device: uint64(stat.Dev), inode: stat.Ino}, true //nolint:unconvert // dev_t differs by architecture.
}

func unixPeer(connection *net.UnixConn) (Peer, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, ErrUnavailable
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := rawConnection.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credentials == nil {
		return Peer{}, ErrUnavailable
	}
	peer := Peer{PID: int(credentials.Pid), UID: int(credentials.Uid), GID: int(credentials.Gid)}
	if peer.PID <= 1 || peer.UID < 0 || peer.GID < 0 {
		return Peer{}, ErrUnavailable
	}
	return peer, nil
}

func boundedDeadline(ctx context.Context, configured time.Duration) time.Time {
	if configured <= 0 {
		configured = defaultTimeout
	}
	if configured > maximumTimeout {
		configured = maximumTimeout
	}
	deadline := time.Now().Add(configured)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func classifyClientError(ctx context.Context, err error) error {
	if ctx != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextError(contextErr)
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return ErrTimeout
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, ErrTimeout) {
		return ErrTimeout
	}
	if errors.Is(err, ErrProtocol) {
		return ErrProtocol
	}
	return ErrUnavailable
}

func contextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrCanceled
}
