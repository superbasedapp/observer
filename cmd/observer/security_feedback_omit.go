//go:build sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"io"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_feedback_omit.go replaces security_feedback.go in a build
// without the security module: the post-tool seam writes every reply
// unchanged and no post-tool event has a feedback handler.

func securityPostFeedback(_ context.Context, w io.Writer, _, _ string, _, reply []byte, _ string) {
	_, _ = w.Write(reply)
}

func securityPostFeedbackWriter(_ context.Context, w io.Writer, _, _ string, _ []byte, _ string) io.Writer {
	return w
}

func handlePostFeedbackHook(_ context.Context, _, _, _, _ string, _ io.Reader, _, _ io.Writer) bool {
	return false
}

func feedbackOptInRoute(_, _, _ string) bool { return false }

// securityExplainDash is nil without the security module: the dashboard's
// explain route answers 404.
func securityExplainDash(string, *sql.DB) dashapi.SecurityExplain { return nil }

// securityExplainFixDash is nil for the same reason: the drawer's "Suggest a
// fix" answers compiled out.
func securityExplainFixDash(string, *sql.DB) dashapi.SecurityExplain { return nil }
