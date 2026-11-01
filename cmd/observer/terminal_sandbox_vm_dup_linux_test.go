//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "syscall"

func unixDup(fd int) (int, error) { return syscall.Dup(fd) }
