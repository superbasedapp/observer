package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
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
	if !errors.As(err, &visible) {
		return false
	}
	message := strings.TrimSpace(visible.launcherMessage())
	if message == "" {
		return false
	}
	_, _ = fmt.Fprintln(stderr, message)
	return true
}
