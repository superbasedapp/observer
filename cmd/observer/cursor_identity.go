package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	cursorCreateChatTimeout     = 10 * time.Second
	cursorCreateChatOutputLimit = 256
	cursorCreateChatWaitDelay   = 250 * time.Millisecond
)

type cursorCreateChatConfig struct {
	timeout     time.Duration
	outputLimit int
	waitDelay   time.Duration
}

func defaultCursorCreateChatConfig() cursorCreateChatConfig {
	return cursorCreateChatConfig{
		timeout:     cursorCreateChatTimeout,
		outputLimit: cursorCreateChatOutputLimit,
		waitDelay:   cursorCreateChatWaitDelay,
	}
}

// cursorFreshLaunchEligible reports whether args unambiguously select a fresh
// interactive Cursor Agent chat. It understands only the option grammar
// grounded in the installed cursor-agent help. Unknown or optional-value
// options abstain so identity allocation cannot change an ambiguous command.
func cursorFreshLaunchEligible(args []string) bool {
	requiredValue := map[string]bool{
		"--api-key":       true,
		"-H":              true,
		"--header":        true,
		"-e":              true,
		"--endpoint":      true,
		"--output-format": true,
		"--mode":          true,
		"--model":         true,
		"--sandbox":       true,
		"--workspace":     true,
		"--add-dir":       true,
		"--plugin-dir":    true,
		"--worktree-base": true,
	}
	boolean := map[string]bool{
		"-v":                      true,
		"--version":               true,
		"-p":                      true,
		"--print":                 true,
		"--stream-partial-output": true,
		"--plan":                  true,
		"--continue":              true,
		"--list-models":           true,
		"-f":                      true,
		"--force":                 true,
		"--yolo":                  true,
		"--auto-review":           true,
		"--approve-mcps":          true,
		"--trust":                 true,
		"--skip-worktree-setup":   true,
		"-h":                      true,
		"--help":                  true,
	}
	selectsOtherChat := map[string]bool{
		"--resume":   true,
		"-w":         true,
		"--worktree": true,
	}
	skipBoolean := map[string]bool{
		"-v":            true,
		"--version":     true,
		"-p":            true,
		"--print":       true,
		"--continue":    true,
		"--list-models": true,
		"-h":            true,
		"--help":        true,
	}

	firstPositional := true
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			return true
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			if firstPositional && cursorSubcommands[tok] {
				return false
			}
			firstPositional = false
			continue
		}

		name, _, joined := splitFlagEq(tok)
		if selectsOtherChat[name] {
			return false
		}
		if boolean[name] {
			if joined {
				return false
			}
			if skipBoolean[name] {
				return false
			}
			continue
		}
		if !requiredValue[name] {
			return false
		}
		if joined {
			if _, value, _ := splitFlagEq(tok); value == "" {
				return false
			}
			continue
		}
		if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
			return false
		}
		i++
	}
	return true
}

// cursorBoundedBuffer retains at most max bytes while continuing to drain the
// child pipe. The overflow bit makes excess output a hard parse failure without
// allowing a noisy vendor process to grow observer memory.
type cursorBoundedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *cursorBoundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.overflow = true
	}
	return n, nil
}

func (b *cursorBoundedBuffer) String() string { return b.buf.String() }

// allocateCursorFreshSession asks the already-resolved Cursor Agent binary to
// create an empty local chat, then prepends its exact native resume argument.
// It abstains unless the trusted terminal OOB channel is active and args
// unambiguously describe a fresh interactive chat.
func allocateCursorFreshSession(ctx context.Context, bin, dir string, args []string) ([]string, string, error) {
	return allocateCursorFreshSessionWithConfig(ctx, bin, dir, args, defaultCursorCreateChatConfig())
}

func allocateCursorFreshSessionWithConfig(
	ctx context.Context,
	bin, dir string,
	args []string,
	cfg cursorCreateChatConfig,
) ([]string, string, error) {
	if !oobChannelActive() || !cursorFreshLaunchEligible(args) {
		return args, "", nil
	}
	allocationDir, ok := cursorFreshAllocationDir(args, dir)
	if !ok {
		return args, "", nil
	}
	if cfg.timeout <= 0 || cfg.outputLimit <= 0 || cfg.waitDelay < 0 {
		return args, "", errors.New("cursor fresh chat allocation has invalid bounds")
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	var stdout, stderr cursorBoundedBuffer
	stdout.max = cfg.outputLimit
	stderr.max = cfg.outputLimit
	create := exec.CommandContext(runCtx, bin, "create-chat")
	create.Dir = allocationDir
	create.Env = scrubOOBEnv(os.Environ())
	create.Stdout = &stdout
	create.Stderr = &stderr
	create.WaitDelay = cfg.waitDelay
	runErr := create.Run()

	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return args, "", errors.New("cursor fresh chat allocation timed out")
	case errors.Is(runCtx.Err(), context.Canceled):
		return args, "", errors.New("cursor fresh chat allocation canceled")
	case stdout.overflow || stderr.overflow:
		return args, "", errors.New("cursor fresh chat allocation returned oversized output")
	case runErr != nil:
		return args, "", errors.New("cursor fresh chat allocation failed")
	}

	sessionID, err := parseCursorCreateChatOutput(stdout.String())
	if err != nil {
		return args, "", err
	}
	return append([]string{"--resume=" + sessionID}, args...), sessionID, nil
}

// cursorFreshAllocationDir returns the directory Cursor Agent will use as the
// primary workspace before opening the interactive chat store. An explicit
// absolute --workspace path is exact. A saved-workspace name or relative value
// is ambiguous without reimplementing Cursor's private workspace registry, so
// allocation abstains for those forms.
func cursorFreshAllocationDir(args []string, childDir string) (string, bool) {
	workspace := ""
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			break
		}
		name, value, joined := splitFlagEq(tok)
		if name == "--workspace" {
			if workspace != "" {
				return "", false
			}
			if !joined {
				i++
				if i >= len(args) {
					return "", false
				}
				value = args[i]
			}
			workspace = value
			continue
		}
		if cursorOptionRequiresValue(name) && !joined {
			i++
		}
	}
	if workspace == "" {
		return childDir, true
	}
	if !filepath.IsAbs(workspace) {
		return "", false
	}
	return filepath.Clean(workspace), true
}

func cursorOptionRequiresValue(name string) bool {
	switch name {
	case "--api-key", "-H", "--header", "-e", "--endpoint", "--output-format", "--mode", "--model",
		"--sandbox", "--workspace", "--add-dir", "--plugin-dir", "--worktree-base":
		return true
	default:
		return false
	}
}

func parseCursorCreateChatOutput(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("cursor fresh chat allocation returned empty output")
	}
	if strings.Count(raw, "\n") != 1 || !strings.HasSuffix(raw, "\n") || strings.Contains(raw, "\r") {
		return "", errors.New("cursor fresh chat allocation returned unexpected output")
	}
	line := strings.TrimSuffix(raw, "\n")
	id, err := uuid.Parse(line)
	if err != nil || id.String() != line || id.Version() != 4 || id.Variant() != uuid.RFC4122 {
		return "", errors.New("cursor fresh chat allocation returned an invalid id")
	}
	return line, nil
}
