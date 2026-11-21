package secimage

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Sink is where a read writes the allow-listed files. Every name is a
// cleaned relative path with forward slashes that Wanted accepted (or one
// of its parent directories). A Sink writes regular files and directories
// only, never a link.
type Sink interface {
	// Create creates (or truncates) a regular file, making its parents.
	Create(name string) (io.WriteCloser, error)
	// Open opens an extracted file for reading.
	Open(name string) (io.ReadCloser, error)
	// Remove removes an extracted file; a missing one is not an error.
	Remove(name string) error
	// MkdirAll makes a directory and its parents.
	MkdirAll(name string) error
}

// DirSink is the Sink over a run directory, every operation confined to it
// by os.Root (a name that would resolve outside it is refused by the
// runtime, whatever the directory holds).
type DirSink struct{ root *os.Root }

// NewDirSink opens dir (which must exist) as a sink. Close releases it.
func NewDirSink(dir string) (*DirSink, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("secimage.NewDirSink: %w", err)
	}
	return &DirSink{root: r}, nil
}

// Close releases the directory.
func (s *DirSink) Close() error { return s.root.Close() }

func osName(name string) string { return filepath.FromSlash(name) }

// Create implements Sink.
func (s *DirSink) Create(name string) (io.WriteCloser, error) {
	if dir := path.Dir(name); dir != "." {
		if err := s.root.MkdirAll(osName(dir), 0o700); err != nil {
			return nil, err
		}
	}
	return s.root.OpenFile(osName(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// Open implements Sink.
func (s *DirSink) Open(name string) (io.ReadCloser, error) { return s.root.Open(osName(name)) }

// Remove implements Sink.
func (s *DirSink) Remove(name string) error {
	err := s.root.Remove(osName(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// MkdirAll implements Sink.
func (s *DirSink) MkdirAll(name string) error { return s.root.MkdirAll(osName(name), 0o700) }

// maxOSReleaseBytes bounds the os-release file read back.
const maxOSReleaseBytes = 64 << 10

// ParseOSRelease parses an os-release(5) file: KEY=VALUE lines, values
// unquoted (single or double quotes, backslash escapes inside double
// quotes), comments and malformed lines skipped. Keys and values are
// metadata the caller maps through a closed table, never trusted text.
func ParseOSRelease(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxOSReleaseBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !validKey(k) {
			continue
		}
		out[k] = unquote(strings.TrimSpace(v))
	}
	return out
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		in := v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				i++
			}
			b.WriteByte(in[i])
		}
		return b.String()
	}
	return v
}

// finishOSRelease is the shared tail of both readers: etc/ always exists,
// usr/lib/os-release is copied to etc/os-release when that one is absent
// (or was a symlink, which a reader never extracts), and the result is
// parsed.
func finishOSRelease(dst Sink, have map[string]bool, res *Result) error {
	if err := dst.MkdirAll("etc"); err != nil {
		return refuse(ReasonOutputFailed, "etc: %v", err)
	}
	if !have["etc/os-release"] && have["usr/lib/os-release"] {
		if err := copyWithin(dst, "usr/lib/os-release", "etc/os-release", maxOSReleaseBytes); err != nil {
			return refuse(ReasonOutputFailed, "os-release: %v", err)
		}
		have["etc/os-release"] = true
		res.OSReleaseCopied = true
	}
	if have["etc/os-release"] {
		f, err := dst.Open("etc/os-release")
		if err != nil {
			return refuse(ReasonOutputFailed, "os-release: %v", err)
		}
		res.OSRelease = ParseOSRelease(f)
		_ = f.Close()
	}
	return nil
}

// copyWithin copies one extracted file to another name in the sink.
func copyWithin(dst Sink, from, to string, limit int64) error {
	r, err := dst.Open(from)
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := dst.Create(to)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, io.LimitReader(r, limit))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return err
}
