package hook

import (
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ToolGateDialectClinePlugin is the Cline CLI plugin's beforeTool gate
// (the internal/hook/pluginshim "cline" shape; see promptclineplugin.go for
// the live grounding). The plugin sends the plugin envelope (tool_name,
// tool_input, session_id, cwd) and maps the reply: deny is {skip:true,
// reason}, a per-call refusal the run survives (the model gets the reason);
// ask is {policy:{autoApprove:false}}, Cline's own y/N approval. Unlike the
// file hook's cancel (ToolGateDialectCline), no verdict stops the run.
const ToolGateDialectClinePlugin = "cline-plugin-pretool"

// clinePluginToolGate is the dialect's table row. Tool names arrive in the
// CLI vocabulary the shared SDK runtime uses (run_commands, read_files,
// editor, apply_patch), the same names the file hook carried, so the
// extension's vocabulary is the fallback exactly as on that row.
var clinePluginToolGate = toolGateDialect{
	extract: shapedToolExtractor(toolPayloadShape{
		session: []string{"session_id"}, cwd: []string{"cwd"},
		tool: []string{"tool_name"}, input: []string{"tool_input"},
		vocab: []string{models.ToolCline},
	}, nil),
	block: func(em guard.Emission, _ string) any {
		return PluginReply{Decision: em.Permission, Reason: em.Reason}
	},
	allow: PluginReply{Decision: "allow"},
}
