package sectrust

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

var (
	// reBaseURLEnv names a variable that redirects where an agent sends its
	// API traffic.
	reBaseURLEnv = regexp.MustCompile(`(?i)^(anthropic|openai|gemini|google_gemini|google_vertex|azure_openai|openrouter|codex|mistral|deepseek|groq|xai|ollama|litellm)_(base_url|api_base|api_base_url|endpoint|host)$|^(anthropic_bedrock_base_url|anthropic_vertex_base_url|openai_api_base|code_assist_endpoint)$`)
	// reBaseURLKey names a config key that holds a provider base URL.
	reBaseURLKey = regexp.MustCompile(`(?i)^(base_?url|api_?base(_?url)?|openai-api-base|anthropic-api-base|endpoint|apiendpoint)$`)
	// reConfigDirEnv names a variable that moves an agent's or Observer's
	// config, home or binary (plan section 5.1 item 6: the plugin shim
	// honours OBSERVER_BIN and OBSERVER_CONFIG).
	reConfigDirEnv = regexp.MustCompile(`(?i)^(codex_home|claude_config_dir|gemini_cli_home|gemini_dir|opencode_config|opencode_config_dir|opencode_config_content|xdg_config_home|xdg_data_home|qwen_home|kiro_home|cursor_config_dir|copilot_home|observer_bin|observer_config)$`)
	// reInjectEnv names a variable that injects code into a process or
	// into git.
	reInjectEnv = regexp.MustCompile(`(?i)^(node_options|ld_preload|ld_library_path|dyld_insert_libraries|bash_env|env|pythonstartup|pythonpath|perl5opt|rubyopt|git_config_parameters|git_config_count|git_config_key_\d+|git_config_value_\d+|git_ssh_command|git_external_diff|git_askpass|git_exec_path|git_dir|git_work_tree|npm_config_.*script.*|prompt_command)$`)
)

// loadRule is one row of the loads-code table: a code-injection variable
// whose value makes a process run or load code from files the reason's
// digest cannot cover (a module path, a preloaded library, a required
// script). value, when set, must also pass.
type loadRule struct {
	name  *regexp.Regexp
	value func(string) bool
}

// loadRules is the loads-code table. A code-injection variable no row
// matches (GIT_DIR, GIT_WORK_TREE, NODE_OPTIONS with no loader flag) only
// changes how a process behaves.
var loadRules = []loadRule{
	{name: regexp.MustCompile(`(?i)^(ld_preload|ld_library_path|dyld_insert_libraries|bash_env|env|pythonstartup|pythonpath|perl5opt|rubyopt|git_config_parameters|git_config_count|git_config_key_\d+|git_config_value_\d+|git_ssh_command|git_external_diff|git_askpass|git_exec_path|npm_config_.*script.*|prompt_command)$`)},
	{name: regexp.MustCompile(`(?i)^node_options$`), value: nodeOptionsLoad},
}

// nodeLoaderFlags are the NODE_OPTIONS flags that load a module.
var nodeLoaderFlags = []string{"-r", "--require", "--import", "--loader", "--experimental-loader"}

// nodeOptionsLoad reports whether a NODE_OPTIONS value loads a module.
func nodeOptionsLoad(value string) bool {
	for _, f := range strings.Fields(value) {
		flag, _, _ := strings.Cut(f, "=")
		for _, l := range nodeLoaderFlags {
			if flag == l {
				return true
			}
		}
	}
	return false
}

// envLoadsCode reports whether a code-injection variable loads code
// (loadRules).
func envLoadsCode(name, value string) bool {
	for _, r := range loadRules {
		if r.name.MatchString(name) {
			return r.value == nil || r.value(value)
		}
	}
	return false
}

// envRule is one row of the variable-name table: the first row whose name
// pattern matches (and whose value test passes) raises its code.
type envRule struct {
	code  string
	name  *regexp.Regexp
	value func(string) bool
}

// envRules is the ordered variable-name table, shared by dotenv files and
// settings env blocks (including VS Code's terminal.integrated.env.*).
var envRules = []envRule{
	{code: "base_url_override", name: reBaseURLEnv, value: remoteURL},
	{code: "config_dir_redirect", name: reConfigDirEnv},
	{code: "process_injection_env", name: reInjectEnv},
}

// envVar judges one variable. withExcerpt is false for a dotenv file,
// whose values can be credentials: there only the name is reported.
func (c *checker) envVar(file, key, name, value string, withExcerpt bool) {
	for _, r := range envRules {
		if !r.name.MatchString(name) {
			continue
		}
		if r.value != nil && !r.value(value) {
			return
		}
		x := Reason{Code: r.code, File: file, Key: key, value: value, runs: r.code == "process_injection_env" && envLoadsCode(name, value)}
		if withExcerpt {
			x.Excerpt = excerpt(value)
			if r.code == "base_url_override" {
				x.Excerpt = excerpt(redactURL(value))
			}
		}
		c.add(x)
		return
	}
}

// envFile judges a dotenv file by variable name.
func (c *checker) envFile(file string, data []byte) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), MaxFileBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		c.envVar(file, name, name, val, false)
	}
}
