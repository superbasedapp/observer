//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/intervention/inspectionbroker"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	cancel()
	if err != nil {
		// run returns only closed stage errors, never underlying OS or peer data.
		fmt.Fprintln(os.Stderr, "observer-node-inspection:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("observer-node-inspection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	uid := flags.Int("target-uid", -1, "enrolled developer UID")
	gid := flags.Int("target-gid", -1, "enrolled developer primary GID")
	unit := flags.String("controller-unit", "observer.service", "root-managed Observer system service")
	executable := flags.String("controller-executable", "/usr/local/bin/observer", "root-owned installed Observer executable")
	socket := flags.String("socket", "", "root-owned runtime socket path")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *uid <= 0 || *gid < 0 ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]*\.service$`).MatchString(*unit) {
		return errors.New("invalid arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("dedicated root service required")
	}
	if *socket == "" {
		*socket = inspectionbroker.DefaultSocketPath(*uid)
	}
	if !filepath.IsAbs(*socket) || filepath.Clean(*socket) != *socket || !filepath.IsAbs(*executable) {
		return errors.New("invalid service paths")
	}
	if _, err := rootExecutableIdentity(*executable); err != nil {
		return errors.New("installed controller identity unavailable")
	}
	listener, unlock, err := listenPrivate(*socket, *gid)
	if err != nil {
		return errors.New("private listener unavailable")
	}
	defer unlock()
	defer listener.Close()
	authorizer := serviceAuthorizer{uid: *uid, unit: *unit, executable: *executable, service: readSystemService}
	server := inspectionbroker.Server{TargetUID: *uid, AuthorizePeer: authorizer.authorize}
	if err := server.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		return errors.New("identity service stopped")
	}
	return nil
}

func rootDirectory(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return errors.New("untrusted directory")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errors.New("untrusted directory")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func listenPrivate(path string, gid int) (*net.UnixListener, func(), error) {
	dir := filepath.Dir(path)
	if err := rootDirectory(filepath.Dir(dir)); err != nil {
		return nil, nil, err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	if err := rootDirectory(dir); err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, nil, err
	}
	unlock := func() { _ = unix.Close(fd) }
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		st.Mode&0o077 != 0 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		unlock()
		return nil, nil, errors.New("service lock unavailable")
	}
	if info, err := os.Lstat(path); err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode()&os.ModeSocket == 0 || os.Remove(path) != nil {
			unlock()
			return nil, nil, errors.New("stale listener cannot be replaced")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		unlock()
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		unlock()
		return nil, nil, err
	}
	if os.Chown(path, 0, gid) != nil || os.Chmod(path, 0o660) != nil {
		_ = listener.Close()
		unlock()
		return nil, nil, errors.New("listener permissions unavailable")
	}
	return listener, unlock, nil
}
