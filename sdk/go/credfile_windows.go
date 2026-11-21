//go:build windows

package superbased

// readOwnerOnlyFile refuses on Windows: the machine has no hardened file
// store there (contract destination.md section 4.1), so the key comes from
// SUPERBASED_API_KEY.
func readOwnerOnlyFile(path string, limit int64) ([]byte, string) {
	return nil, "credential files are not read on Windows; set SUPERBASED_API_KEY"
}
