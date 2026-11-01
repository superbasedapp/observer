//go:build windows

package main

import "syscall"

// The system's own text for a Win32 error code: syscall.Errno's Error on
// Windows is FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM), so code 5 reads
// "Access is denied." and 1114 "A dynamic link library (DLL) initialization
// routine failed.".
func init() { boxWin32Message = func(code uint32) string { return syscall.Errno(code).Error() } }
