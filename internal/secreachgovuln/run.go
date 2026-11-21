//go:build !sbo_omit_security_reach_go && !sbo_omit_security

package secreachgovuln

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/vuln/scan"
)

// Compiled reports whether golang.org/x/vuln is linked into this binary.
const Compiled = true

// Run runs govulncheck in binary mode over one binary against the local
// database at dbDir and writes its JSON stream to out (govulncheck's own
// progress text goes to errOut). An error is a failed run: the caller reads
// the binary "unknown", never clean.
func Run(ctx context.Context, dbDir, binary string, out, errOut io.Writer) error {
	u, err := DBURL(dbDir)
	if err != nil {
		return err
	}
	args, err := Args(u, binary)
	if err != nil {
		return err
	}
	cmd := scan.Command(ctx, args...)
	cmd.Stdout, cmd.Stderr = out, errOut
	// Never the process's environment (nil would mean os.Environ()).
	cmd.Env = []string{}
	cmd.Stdin = emptyReader{}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("secreachgovuln.Run: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("secreachgovuln.Run: %w", err)
	}
	return nil
}

// emptyReader is govulncheck's stdin: it reads stdin only in convert mode,
// and never the scan child's (the child's request).
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
