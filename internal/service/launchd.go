package service

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LaunchdLabel is the launchd label of the per-user LaunchAgent that
// supervises `observer start` on macOS. It matches the documentation-only
// template in deploy/supervisor/app.superbased.observer.plist.
const LaunchdLabel = "app.superbased.observer"

// LaunchAgentPath is where the per-user agent lives (no admin needed).
func LaunchAgentPath(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
}

// LaunchdLogPath is where the agent's stdout and stderr go. ~/Library/Logs is
// the per-user place Console.app shows, and unlike /tmp it survives a reboot.
func LaunchdLogPath(home string) string {
	return filepath.Join(home, "Library", "Logs", "SuperBased", "observer.log")
}

// LaunchAgentOptions describes how to render the agent.
type LaunchAgentOptions struct {
	// ExecPath is the absolute path to the observer binary (launchd does
	// not use the shell's PATH to find it).
	ExecPath string
	// Args are appended after "start" (the --config/--recipe/--port the
	// operator installed with).
	Args []string
	// LogPath receives stdout and stderr.
	LogPath string
	// Path becomes the agent's PATH, normally the merged login PATH so the
	// daemon finds npm-installed AI tools; "" falls back to DefaultPath.
	Path string
}

// RenderLaunchAgent renders the LaunchAgent plist. The output is
// deterministic, so a re-install with the same inputs is byte-identical.
//
// KeepAlive is SuccessfulExit=false rather than true for the reason the
// template documents: after a successful update handshake the old process
// exits 0 on purpose with the new binary already running, and a hard
// KeepAlive would race launchd's restart against it. A crash still restarts.
func RenderLaunchAgent(o LaunchAgentOptions) string {
	path := o.Path
	if path == "" {
		path = DefaultPath
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<!-- Written by `observer service install`. Remove with `observer service uninstall`. -->\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("  <key>Label</key>\n  <string>" + LaunchdLabel + "</string>\n")
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range append([]string{o.ExecPath, "start"}, o.Args...) {
		b.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString("  </array>\n")
	b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
	b.WriteString("    <key>PATH</key>\n    <string>" + xmlEscape(path) + "</string>\n")
	b.WriteString("  </dict>\n")
	b.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n")
	b.WriteString("  <key>ThrottleInterval</key>\n  <integer>10</integer>\n")
	b.WriteString("  <key>ExitTimeOut</key>\n  <integer>120</integer>\n")
	b.WriteString("  <key>ProcessType</key>\n  <string>Background</string>\n")
	b.WriteString("  <key>StandardOutPath</key>\n  <string>" + xmlEscape(o.LogPath) + "</string>\n")
	b.WriteString("  <key>StandardErrorPath</key>\n  <string>" + xmlEscape(o.LogPath) + "</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

var (
	programArgsRe = regexp.MustCompile(`(?s)<key>ProgramArguments</key>\s*<array>(.*?)</array>`)
	plistStringRe = regexp.MustCompile(`(?s)<string>(.*?)</string>`)
)

// LaunchAgentProgramArguments reads ProgramArguments back out of a plist this
// package rendered, for `observer service upgrade` (which keeps the arguments
// and only moves the executable). ok is false when the file has no array.
func LaunchAgentProgramArguments(plist string) ([]string, bool) {
	m := programArgsRe.FindStringSubmatch(plist)
	if m == nil {
		return nil, false
	}
	var out []string
	for _, s := range plistStringRe.FindAllStringSubmatch(m[1], -1) {
		out = append(out, xmlUnescape(s[1]))
	}
	return out, len(out) > 0
}

// LaunchdDomain is the per-user GUI domain launchctl addresses, "gui/<uid>".
func LaunchdDomain(uid int) string { return "gui/" + strconv.Itoa(uid) }

// LaunchdTarget is the agent's service target, "gui/<uid>/<label>".
func LaunchdTarget(uid int) string { return LaunchdDomain(uid) + "/" + LaunchdLabel }

// Launchctl builds a `launchctl <args...>` command.
func Launchctl(args ...string) Command {
	return Command{Name: "launchctl", Args: append([]string(nil), args...)}
}

// TailLog builds the `tail` command `observer service logs` runs on macOS,
// where the agent writes a plain log file rather than the journal.
func TailLog(path string, follow bool, lines int) Command {
	args := []string{}
	if lines > 0 {
		args = append(args, "-n", strconv.Itoa(lines))
	}
	if follow {
		args = append(args, "-f")
	}
	return Command{Name: "tail", Args: append(args, path)}
}

var (
	xmlEscaper   = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	xmlUnescaper = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")
)

func xmlEscape(s string) string   { return xmlEscaper.Replace(s) }
func xmlUnescape(s string) string { return xmlUnescaper.Replace(s) }
