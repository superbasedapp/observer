package projectfs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
)

// MaxLockfileBytes is the default size cap of a lockfile read (the
// dashboard drawer's cap).
const MaxLockfileBytes = 32 << 20

// Read reads the project-relative file rel under root, at most max bytes.
// A rel that is absolute, has a volume name or climbs out ("..") and a
// file whose real path (symlinks resolved on both sides) is not under the
// root's real path are secdepdetail.ErrOutsideProject; a larger file is
// secdepdetail.ErrFileTooLarge; anything else that cannot be read is
// returned wrapped (unreadable). A non-regular file is unreadable.
func Read(root, rel string, max int64) ([]byte, error) {
	slash := filepath.ToSlash(rel)
	if rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(slash, "/") || filepath.VolumeName(rel) != "" {
		return nil, secdepdetail.ErrOutsideProject
	}
	for _, seg := range strings.Split(slash, "/") {
		if seg == ".." {
			return nil, secdepdetail.ErrOutsideProject
		}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("projectfs.Read: %w", err)
	}
	realFile, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(slash)))
	if err != nil {
		return nil, fmt.Errorf("projectfs.Read: %w", err)
	}
	inside, err := filepath.Rel(realRoot, realFile)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
		return nil, secdepdetail.ErrOutsideProject
	}
	f, err := os.Open(realFile) //nolint:gosec // G304: the real path was checked to lie under the project root just above.
	if err != nil {
		return nil, fmt.Errorf("projectfs.Read: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("projectfs.Read: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("projectfs.Read: %w", fs.ErrInvalid)
	}
	if st.Size() > max {
		return nil, secdepdetail.ErrFileTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("projectfs.Read: %w", err)
	}
	if int64(len(b)) > max {
		return nil, secdepdetail.ErrFileTooLarge
	}
	return b, nil
}
