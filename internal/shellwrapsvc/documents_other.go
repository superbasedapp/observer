//go:build !windows

package shellwrapsvc

import "errors"

// errNoWindowsLookup: the Windows Documents-folder lookups exist only on
// Windows. Elsewhere (a test that sets Service.GOOS = "windows") the ladder
// falls through to <home>\Documents.
var errNoWindowsLookup = errors.New("shellwrapsvc: Windows known-folder lookup unavailable on this OS")

func osDocumentsKnownFolder() (string, error) { return "", errNoWindowsLookup }

func osDocumentsShellFolder() (string, error) { return "", errNoWindowsLookup }
