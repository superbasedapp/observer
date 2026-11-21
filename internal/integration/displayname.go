package integration

// displayname.go is the ONE server-side owner of a coding tool's product name
// (T-201). The org server used to hand raw adapter ids ("claude-code") to
// every consumer that is not a browser page, so the admin assistant, budget
// alert webhooks and emails, and the Agent Access label resolver all read ids
// where the dashboard read names. The dashboards keep their own copy of the
// same names in shared/lib/tools.ts (they also carry colours and provider
// classes); TestDisplayNamesMatchSharedToolRegistry pins the two tables
// together, so a rename lands in both or fails loudly.

// displayNames maps a tool id to its product name. It covers every registry
// row plus the ids the dashboards name that have no registry row of their own
// ("gemini", the Gemini API lane the dashboards render beside "gemini-cli").
var displayNames = map[string]string{
	"claude-code":      "Claude Code",
	"codex":            "Codex",
	"cursor":           "Cursor",
	"cline":            "Cline",
	"copilot":          "Copilot",
	"copilot-cli":      "Copilot CLI",
	"cowork":           "Cowork",
	"antigravity":      "Antigravity",
	"opencode":         "OpenCode",
	"openclaw":         "OpenClaw",
	"pi":               "Pi",
	"gemini":           "Gemini",
	"gemini-cli":       "Gemini CLI",
	"cline-cli":        "Cline CLI",
	"antigravity-cli":  "Antigravity CLI",
	"hermes":           "Hermes",
	"kilo-code":        "Kilo Code",
	"kilo-code-cli":    "Kilo CLI",
	"qwen-code":        "Qwen Code",
	"kiro-cli":         "Kiro CLI",
	"crush":            "Crush",
	"kimi-code":        "Kimi Code",
	"grok":             "Grok",
	"devin":            "Devin",
	"aider":            "Aider",
	"qoder":            "Qoder",
	"goose":            "goose",
	"droid":            "droid",
	"open-interpreter": "Open Interpreter",
	"command-code":     "Command Code",
	"zcode":            "zcode",
	"mistral-code":     "Mistral Code",
	"freebuff":         "Freebuff",
	"grokbot":          "Grok Bot",
	"kiro-crew":        "Kiro Crew",
	"muse":             "Muse",
	"prime-agent":      "Prime Agent",
	"deepseek":         "DeepSeek",
	"junie":            "Junie",
	"poolside":         "Poolside",
	"zed":              "Zed",
	"autohand":         "Autohand Code",
	"ibm-bob":          "IBM Bob",
	"cortex-code":      "Cortex Code",
	"codebuddy":        "CodeBuddy Code",
	"deepagents-code":  "Deep Agents Code",
	"dimcode":          "DimCode",
	"dirac":            "Dirac",
	"kimchi":           "Kimchi",
	"stakpak":          "Stakpak",
	"vtcode":           "VT Code",
	"custom-agent":     "Own agent",
	"chatgpt-web":      "ChatGPT (web)",
	"claude-web":       "Claude (web)",
	"perplexity-web":   "Perplexity (web)",
	"gemini-web":       "Gemini (web)",
	"copilot-web":      "Copilot (web)",
}

// DisplayName returns the product name of a coding tool id ("Claude Code"
// for "claude-code"), or the id itself when the tool has no known name, so a
// caller can always render the result. It never guesses a name from the id.
func DisplayName(tool string) string {
	if n, ok := displayNames[tool]; ok {
		return n
	}
	return tool
}

// HasDisplayName reports whether tool has a known product name (so a caller
// can tell a resolved name from the id echoed back).
func HasDisplayName(tool string) bool {
	_, ok := displayNames[tool]
	return ok
}
