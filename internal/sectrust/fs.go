package sectrust

import (
	"errors"
	"io/fs"
)

// FS is the read-only view of one repository the check runs against. Every
// path is slash-separated and relative to the repository root ("" is the
// root itself). Implementations must never write.
type FS interface {
	// Lstat describes rel without following a final symlink.
	Lstat(rel string) (fs.FileInfo, error)
	// Stat describes rel, following symlinks.
	Stat(rel string) (fs.FileInfo, error)
	// ReadFile reads rel, following symlinks, and fails when it holds more
	// than max bytes.
	ReadFile(rel string, max int64) ([]byte, error)
	// ReadDir lists rel, sorted by name.
	ReadDir(rel string) ([]fs.DirEntry, error)
	// HashFile streams rel, following symlinks, into a SHA-256 and returns
	// the hex sum and the byte count; it fails when rel holds more than max
	// bytes. It covers files over the read cap, so a large file still gets
	// a whole-file digest the developer can accept.
	HashFile(rel string, max int64) (sum string, size int64, err error)
	// Escapes reports whether rel, with every symlink followed, resolves
	// outside the repository root. A link that cannot be resolved (dangling,
	// a loop, no permission) escapes.
	Escapes(rel string) bool
}

// linkReader is the optional capability of an FS that can read a symlink's
// own target text (the OS view can; the in-memory view holds no links). A
// symlink_escape digest covers that text when the FS offers it.
type linkReader interface {
	// Readlink returns the target rel's symlink names, as written.
	Readlink(rel string) (string, error)
}

// errTooLarge is returned by ReadFile and HashFile for a file over the cap
// they were given.
var errTooLarge = errors.New("sectrust: file over the read cap")
