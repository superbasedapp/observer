//go:build windows

package sandboxhcs

import "golang.org/x/sys/windows"

// loader_windows.go loads computecore.dll from System32 only (never the
// application directory or the search path) and resolves its functions
// lazily; no function is called here. A per-run helper, never the daemon,
// builds it.

type sysLibrary struct{ dll *windows.LazyDLL }

func (s sysLibrary) Has(name string) bool { return s.dll.NewProc(name).Find() == nil }

// NewSystemLoader is the real loader.
func NewSystemLoader() *Loader {
	return NewLoader(func() (Library, error) {
		dll := windows.NewLazySystemDLL("computecore.dll")
		if err := dll.Load(); err != nil {
			return nil, err
		}
		return sysLibrary{dll: dll}, nil
	})
}
