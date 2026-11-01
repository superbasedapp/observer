package sandboxvm

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// fakeSuperblock is an image prefix with an ext4 superblock: magic and the
// incompat word, the needs_recovery bit set when dirty.
func fakeSuperblock(magic uint16, incompat uint32) []byte {
	b := make([]byte, 4096)
	binary.LittleEndian.PutUint16(b[ext4SuperOffset+ext4MagicOffset:], magic)
	binary.LittleEndian.PutUint32(b[ext4SuperOffset+ext4IncompatOffset:], incompat)
	return b
}

// TestImageNeedsRecovery pins the read-back's guard: an image whose journal
// still needs recovery (the guest never unmounted it) is reported, a closed
// one is not, and anything that is not ext4 is an error.
func TestImageNeedsRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		img     []byte
		want    bool
		wantErr bool
	}{
		{"closed", fakeSuperblock(ext4Magic, 0x0002|0x0040|0x0080), false, false},
		{"left mounted", fakeSuperblock(ext4Magic, 0x0002|ext4IncompatRecover|0x0040), true, false},
		{"not ext4", fakeSuperblock(0x1234, ext4IncompatRecover), false, true},
		{"short", make([]byte, 1100), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ImageNeedsRecovery(bytes.NewReader(tc.img))
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("ImageNeedsRecovery = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestImageNeedsRecoveryOnAFreshImage reads a real mkfs.ext4 image (the
// shape the host writes before boot): a closed image.
func TestImageNeedsRecoveryOnAFreshImage(t *testing.T) {
	mkfs := ""
	for _, p := range []string{"/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"} {
		if _, err := os.Stat(p); err == nil {
			mkfs = p
			break
		}
	}
	if mkfs == "" {
		t.Skip("no mkfs.ext4 on this host")
	}
	img := filepath.Join(t.TempDir(), "ws.img")
	if out, err := exec.Command(mkfs, "-q", "-F", img, "8M").CombinedOutput(); err != nil {
		t.Skipf("mkfs.ext4: %v %s", err, out)
	}
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dirty, err := ImageNeedsRecovery(f)
	if err != nil || dirty {
		t.Fatalf("a fresh image: dirty %v, %v", dirty, err)
	}
}
