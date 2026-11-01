//go:build !sbo_omit_security && sbo_omit_judge_client

package main

import "github.com/marmutapp/superbased-observer/internal/config"

// security_feedback_judge_omit.go: with the judge client compiled out the
// explain flow has no judge, and says so (nothing is sent).
func securityExplainJudgeFor(config.Config) *securityExplainJudge { return nil }
