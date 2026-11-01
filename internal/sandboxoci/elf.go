package sandboxoci

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"strings"
)

// elf.go reads what tool delivery needs from a host binary, over an
// injected reader: its ELF program interpreter (its dynamic loader), or the
// interpreter a script's #! line names.

// ErrNotELF is returned for a file that is not an ELF binary.
var ErrNotELF = errors.New("sandboxoci: not an ELF binary")

// ELFInterp returns the binary's PT_INTERP ("" for a static binary).
func ELFInterp(r io.ReaderAt) (string, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return "", ErrNotELF
	}
	defer func() { _ = f.Close() }()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		b := make([]byte, p.Filesz)
		if _, err := p.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return string(bytes.TrimRight(b, "\x00")), nil
	}
	return "", nil
}

// Shebang returns the program a script's first line names, following
// `/usr/bin/env <name>` to <name>; ok is false when head is not a #! line.
// The name may be bare (resolved on PATH by the caller).
func Shebang(head []byte) (prog string, ok bool) {
	if !bytes.HasPrefix(head, []byte("#!")) {
		return "", false
	}
	line := string(head[2:])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	if strings.HasSuffix(fields[0], "/env") {
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "-") {
				return f, true
			}
		}
		return "", false
	}
	return fields[0], true
}
