package mirrorbase

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// SQLite write-ahead-log constants (https://www.sqlite.org/fileformat2.html
// section 4 "The Write-Ahead Log").
const (
	walMagicLE      = 0x377f0682 // checksums over little-endian words
	walMagicBE      = 0x377f0683 // checksums over big-endian words
	walVersion      = 3007000
	walHeaderSize   = 32
	walFrameHdrSize = 24
	dbHeaderSize    = 100
)

// errWALVersion reports a WAL whose format version this reader does not
// know. SQLite itself refuses such a file, so the mirror does too rather
// than silently dropping committed transactions.
var errWALVersion = errors.New("unsupported WAL format version")

// applyWAL returns the database image that a checkpoint of wal into db
// would produce: every frame up to and including the last valid commit
// frame is written over its page, and the image is resized to the
// commit's database size. Frames after the last commit (an in-flight
// transaction) and frames whose salt or cumulative checksum does not
// verify (a stale tail from an earlier WAL generation, or a torn read)
// are ignored, exactly as SQLite's own WAL recovery ignores them.
//
// db is modified in place (the caller owns a freshly read buffer, and a
// second copy of a large store would double peak memory) and the result
// may alias it. The header's read/write format bytes are set to 1
// (rollback journal) because the in-memory image has no WAL of its own.
// A missing, short or invalid wal leaves the pages unchanged.
func applyWAL(db, wal []byte) ([]byte, error) {
	img := db
	pageSize, err := walPageSize(img, wal)
	if err != nil {
		return nil, err
	}
	if pageSize > 0 {
		img = replayFrames(img, wal, pageSize)
	}
	if len(img) >= dbHeaderSize {
		img[18], img[19] = 1, 1
	}
	return img, nil
}

// walPageSize validates the WAL header and returns its page size, or 0
// when the WAL should be ignored (absent, short, wrong magic, bad header
// checksum). A page size that disagrees with the database header is an
// error: applying such frames would corrupt the image.
func walPageSize(db, wal []byte) (int, error) {
	if len(wal) < walHeaderSize {
		return 0, nil
	}
	magic := binary.BigEndian.Uint32(wal[0:4])
	if magic != walMagicLE && magic != walMagicBE {
		return 0, nil
	}
	if v := binary.BigEndian.Uint32(wal[4:8]); v != walVersion {
		return 0, fmt.Errorf("%w: %d", errWALVersion, v)
	}
	pageSize := int(binary.BigEndian.Uint32(wal[8:12]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return 0, nil
	}
	bigEndian := magic == walMagicBE
	s0, s1 := walChecksum(wal[0:24], bigEndian, 0, 0)
	if s0 != binary.BigEndian.Uint32(wal[24:28]) || s1 != binary.BigEndian.Uint32(wal[28:32]) {
		return 0, nil
	}
	if len(db) >= dbHeaderSize {
		dbPage := int(binary.BigEndian.Uint16(db[16:18]))
		if dbPage == 1 {
			dbPage = 65536
		}
		if dbPage != pageSize {
			return 0, fmt.Errorf("WAL page size %d differs from database page size %d", pageSize, dbPage)
		}
	}
	return pageSize, nil
}

// replayFrames applies every committed, checksum-valid frame of wal to
// img (see applyWAL) and returns the resized image.
func replayFrames(img, wal []byte, pageSize int) []byte {
	bigEndian := binary.BigEndian.Uint32(wal[0:4]) == walMagicBE
	salt := wal[16:24]
	s0 := binary.BigEndian.Uint32(wal[24:28])
	s1 := binary.BigEndian.Uint32(wal[28:32])
	frameSize := walFrameHdrSize + pageSize

	type pending struct {
		pgno uint32
		page []byte
	}
	var txn []pending
	for off := walHeaderSize; off+frameSize <= len(wal); off += frameSize {
		hdr := wal[off : off+walFrameHdrSize]
		page := wal[off+walFrameHdrSize : off+frameSize]
		if !bytes.Equal(hdr[8:16], salt) {
			break
		}
		s0, s1 = walChecksum(hdr[0:8], bigEndian, s0, s1)
		s0, s1 = walChecksum(page, bigEndian, s0, s1)
		if s0 != binary.BigEndian.Uint32(hdr[16:20]) || s1 != binary.BigEndian.Uint32(hdr[20:24]) {
			break
		}
		pgno := binary.BigEndian.Uint32(hdr[0:4])
		if pgno == 0 {
			break
		}
		txn = append(txn, pending{pgno: pgno, page: page})
		commitPages := binary.BigEndian.Uint32(hdr[4:8])
		if commitPages == 0 {
			continue
		}
		for _, p := range txn {
			end := int(p.pgno) * pageSize
			if end > len(img) {
				img = append(img, make([]byte, end-len(img))...)
			}
			copy(img[end-pageSize:end], p.page)
		}
		txn = txn[:0]
		size := int(commitPages) * pageSize
		if size <= len(img) {
			img = img[:size]
		} else {
			img = append(img, make([]byte, size-len(img))...)
		}
	}
	return img
}

// walChecksum continues SQLite's WAL checksum (two 32-bit Fibonacci-
// weighted sums over 8-byte word pairs) across b.
func walChecksum(b []byte, bigEndian bool, s0, s1 uint32) (uint32, uint32) {
	order := binary.ByteOrder(binary.LittleEndian)
	if bigEndian {
		order = binary.BigEndian
	}
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}
