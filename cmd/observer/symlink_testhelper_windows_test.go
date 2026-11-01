//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// symlinkPrivilegeMissing reports the Windows refusal to make a symbolic
// link without Developer Mode or the privilege.
func symlinkPrivilegeMissing(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}
