package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// dashboard_listen_record.go is the daemon's record of the address its
// dashboard listens on (SBX-UPD audit finding 3). A CLI that asks the running
// daemon about its live sandboxed runs reads it, so a daemon started with
// --dashboard-addr, or bound to every interface, is still found rather than
// missed (a missed daemon would have its runs ended by the restart that
// follows). The file is owner-only, beside the node database, written once
// the address is settled and removed at a clean exit while it still names
// this process; a stale one (a crashed daemon) names an address nothing
// answers, which reads as no daemon.

// dashboardListenRecordName is the record's file name beside the database.
const dashboardListenRecordName = "dashboard-listen.json"

// dashboardListenRecordMax bounds the record a reader accepts.
const dashboardListenRecordMax = 4 << 10

// dashboardListenRecord is the record's content.
type dashboardListenRecord struct {
	Addr string `json:"addr"`
	PID  int    `json:"pid"`
}

// dashboardListenRecordPath is the record's path for the database at dbPath.
func dashboardListenRecordPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), dashboardListenRecordName)
}

// writeDashboardListenRecord records addr for this process (a fresh 0600 file
// renamed over the old one) and returns the removal to run at exit, which
// removes the file only while it still names this process.
func writeDashboardListenRecord(dbPath, addr string) (func(), error) {
	p := dashboardListenRecordPath(dbPath)
	b, err := json.Marshal(dashboardListenRecord{Addr: addr, PID: os.Getpid()})
	if err != nil {
		return func() {}, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return func() {}, err
	}
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return func() {}, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return func() {}, err
	}
	return func() {
		if rec, ok := readDashboardListenRecord(dbPath); ok && rec.PID == os.Getpid() {
			_ = os.Remove(p)
		}
	}, nil
}

// readDashboardListenRecord reads the record for the database at dbPath;
// ok=false when there is none or it does not parse.
func readDashboardListenRecord(dbPath string) (dashboardListenRecord, bool) {
	f, err := os.Open(dashboardListenRecordPath(dbPath)) //nolint:gosec // G304: the daemon's own record beside its database
	if err != nil {
		return dashboardListenRecord{}, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, dashboardListenRecordMax))
	if err != nil {
		return dashboardListenRecord{}, false
	}
	var rec dashboardListenRecord
	if json.Unmarshal(b, &rec) != nil || rec.Addr == "" {
		return dashboardListenRecord{}, false
	}
	if _, _, err := net.SplitHostPort(rec.Addr); err != nil {
		return dashboardListenRecord{}, false
	}
	return rec, true
}

// dialableDashboardAddr is the address a local client dials for a dashboard
// listening on addr: a bind to every interface (an empty host, 0.0.0.0 or ::)
// is reached on loopback at the same port.
func dialableDashboardAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// wsaeconnrefused is Windows' WSAECONNREFUSED, which syscall.ECONNREFUSED
// does not match there.
const wsaeconnrefused = syscall.Errno(10061)

// isConnRefused reports whether err is a refused connection: nothing listens
// at the address, which is how a CLI tells "no daemon" from a daemon that
// answered badly.
func isConnRefused(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ECONNREFUSED || errno == wsaeconnrefused
	}
	return false
}
