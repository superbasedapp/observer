package hookctx

import "os"

// HostSource is the operating-system Source of the host path: the hook
// process's own parent id, environment and filesystem. It is the only
// place in this package that touches the operating system. Ancestors is
// left nil: the ancestry walker belongs to the caller (cmd/observer's
// /proc walk) and is passed in Source.Ancestors.
func HostSource() Source {
	return Source{
		ParentPID: os.Getppid,
		Getenv:    os.Getenv,
		Environ:   os.Environ,
		Files: Files{
			ReadFile: os.ReadFile,
			Open:     openOS,
			Stat:     os.Stat,
		},
	}
}

// openOS keeps a nil *os.File out of the File interface on error.
func openOS(path string) (File, error) {
	f, err := os.Open(path) //nolint:gosec // a payload-named path; each reader applies its own name and size checks, as before the seam
	if err != nil {
		return nil, err
	}
	return f, nil
}

var _ File = (*os.File)(nil)
