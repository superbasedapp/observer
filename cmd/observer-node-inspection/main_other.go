//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "observer-node-inspection: Linux is required")
	os.Exit(1)
}
