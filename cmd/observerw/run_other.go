//go:build !windows

package main

import (
	"fmt"
	"os"
)

// run says what observerw is for instead of pretending: it is the Windows
// no-console launcher and has nothing to do elsewhere.
func run(_ []string) int {
	fmt.Fprintln(os.Stderr, "observerw is the Windows no-console launcher; run observer directly on this OS")
	return 2
}
