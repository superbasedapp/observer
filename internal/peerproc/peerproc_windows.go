//go:build windows

package peerproc

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/callerid"
)

const supported = true

var (
	modIPHelper             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHelper.NewProc("GetExtendedTcpTable")
)

const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPIDAll = 5
	errInsufficientBuf  = 122
	// Row sizes of MIB_TCPROW_OWNER_PID and MIB_TCP6ROW_OWNER_PID.
	row4Size = 24
	row6Size = 56
)

// find ignores roots: a Windows box (the MXC rows) has no PID namespace,
// so the caller check refuses every caller while one is live (rule C5),
// and no descendant scan could prove a holder outside it.
func find(_ context.Context, client, server netip.AddrPort, _ map[int]string) (Peer, error) {
	pid, ok := ownerPID(client, server)
	if !ok || pid == 0 {
		return Peer{SocketUID: -1}, ErrNotFound
	}
	return Peer{PID: int(pid), Ancestors: ancestors(int(pid)), SocketUID: -1}, nil
}

// ancestors walks pid's parents over one process snapshot.
func ancestors(pid int) []int { return callerid.Ancestors(pid, snapshotParent(snapshot())) }

// snapshotParent is the parent lookup over a process snapshot. A parent pid
// Windows reports may have been reused by a later process: a real parent
// never started after its child, so such a parent ends the walk.
func snapshotParent(snap map[uint32]uint32) func(child int) (int, bool) {
	return func(child int) (int, bool) {
		p, ok := snap[uint32(child)] //nolint:gosec // G115: a pid from the snapshot
		if !ok || p == 0 {
			return 0, false
		}
		ct, ok1 := creation(uint32(child)) //nolint:gosec // G115: a pid from the snapshot
		pt, ok2 := creation(p)
		if !ok1 || !ok2 || pt > ct {
			return 0, false
		}
		return int(p), true
	}
}

// ownerPID reads the TCP owner table of client's family and returns the
// process owning the row whose local end is client and remote end server.
func ownerPID(client, server netip.AddrPort) (uint32, bool) {
	c, s := netip.AddrPortFrom(client.Addr().Unmap(), client.Port()), netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	family, rowSize := afInet, row4Size
	if c.Addr().Is6() {
		family, rowSize = afInet6, row6Size
	}
	var size uint32
	var buf []byte
	for range 3 {
		var p uintptr
		if len(buf) > 0 {
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := procGetExtendedTCPTable.Call(p, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0)
		if r == 0 && len(buf) > 0 {
			break
		}
		if r != errInsufficientBuf && !(r == 0 && len(buf) == 0) {
			return 0, false
		}
		buf = make([]byte, size)
	}
	if len(buf) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		var local, remote netip.AddrPort
		var pid uint32
		if family == afInet {
			local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[4:8])), port(row[8:12]))
			remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[12:16])), port(row[16:20]))
			pid = binary.LittleEndian.Uint32(row[20:24])
		} else {
			local = netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[0:16])).Unmap(), port(row[20:24]))
			remote = netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[24:40])).Unmap(), port(row[44:48]))
			pid = binary.LittleEndian.Uint32(row[52:56])
		}
		if local == c && remote == s {
			return pid, true
		}
	}
	return 0, false
}

// port decodes a DWORD whose low 16 bits hold a port in network order.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// snapshot maps every process to its parent.
func snapshot() map[uint32]uint32 {
	out := map[uint32]uint32{}
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := windows.Process32First(h, &e); err == nil; err = windows.Process32Next(h, &e) {
		out[e.ProcessID] = e.ParentProcessID
	}
	return out
}

// creation is pid's creation time (100 ns units), false when unreadable.
func creation(pid uint32) (uint64, bool) {
	ct, _, ok := processTimes(pid)
	return ct, ok
}

// processTimes is pid's creation time (100 ns units) and whether it has
// exited, false when unreadable. An exited process stays openable, with
// its creation time, for as long as any handle to it is open (its parent's,
// say); its exit time is then set.
func processTimes(pid uint32) (created uint64, exited, ok bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false, false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, false, false
	}
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), e.HighDateTime != 0 || e.LowDateTime != 0, true
}

// startToken names pid's current start, false when it cannot be read or the
// process has exited (a process object kept by an open handle is not a
// running process).
func startToken(pid int) (string, bool) {
	ct, exited, ok := processTimes(uint32(pid)) //nolint:gosec // G115: a pid this process recorded
	if !ok || exited {
		return "", false
	}
	return strconv.FormatUint(ct, 10), true
}

// envMarker reads no other process's environment on this platform.
func envMarker([]int, []string) (string, bool) { return "", false }
