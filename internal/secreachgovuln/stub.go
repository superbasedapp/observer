//go:build sbo_omit_security_reach_go || sbo_omit_security

package secreachgovuln

import (
	"context"
	"io"
)

// Compiled reports whether golang.org/x/vuln is linked into this binary.
const Compiled = false

// Run answers ErrNotCompiled in a build without x/vuln.
func Run(context.Context, string, string, io.Writer, io.Writer) error { return ErrNotCompiled }
