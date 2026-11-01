//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && !unix && !windows

package main

import "os"

// codeFileID has no file identity on this platform: nothing is cached.
func codeFileID(string, os.FileInfo) (string, bool) { return "", false }
