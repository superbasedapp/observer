package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// visibleLauncherError preserves the internal error chain while carrying the
// bounded message that a launcher may safely show to its terminal user.
// Callers must not derive message from an arbitrary internal error.
type visibleLauncherError struct {
	cause   error
	message string
}

func (e visibleLauncherError) Error() string { return e.cause.Error() }

func (e visibleLauncherError) Unwrap() error { return e.cause }

func (e visibleLauncherError) launcherMessage() string { return e.message }

func newVisibleLauncherError(cause error, message string) error {
	if cause == nil || strings.TrimSpace(message) == "" {
		return cause
	}
	return visibleLauncherError{cause: cause, message: message}
}

type launcherMessageError interface {
	error
	launcherMessage() string
}

// renderSuppressedLauncherError restores only an explicitly safe launcher
// message when Cobra suppressed the executed command's returned error. Normal
// Cobra errors have already been printed and exitErr intentionally stays
// silent, so neither is duplicated here.
func renderSuppressedLauncherError(stderr io.Writer, root, executed *cobra.Command, err error) bool {
	if stderr == nil || root == nil || executed == nil || err == nil ||
		(!root.SilenceErrors && !executed.SilenceErrors) {
		return false
	}
	var visible launcherMessageError
	if errors.As(err, &visible) {
		message := strings.TrimSpace(visible.launcherMessage())
		if message == "" {
			return false
		}
		_, _ = fmt.Fprintln(stderr, message)
		return true
	}
	// A config file that exists but cannot be read is said, never a silent
	// exit 1 (Linux live check 2026-10-23, LIN-1 F3): the path and the
	// operating system's reason, nothing from the file.
	var unreadable *config.ReadError
	if errors.As(err, &unreadable) {
		_, _ = fmt.Fprintf(stderr, "observer %s: cannot read its config file %s: %v\n", executed.Name(), unreadable.Path, unreadable.Err)
		return true
	}
	return false
}
