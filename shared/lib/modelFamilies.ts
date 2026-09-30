// GENERATED from the brand-marks bundle (design/brand-icons/build-brand-marks.mjs) — do not hand-edit the
// table; regenerate. Pure: no DOM, no fetch.
//
// modelFamily(id) walks an ORDERED rule table top-down over the lowercased FULL
// model id, so a family word anywhere wins over a host/router prefix:
//   "cursor-grok-4.6-high"            -> grok
//   "openrouter/deepseek/deepseek-v4" -> deepseek
//   "openrouter/free", "auto"         -> auto (a route, not a model)
// Unmatched ids return null (render the plain ModelId, no mark: never guess).

export type ModelFamilyId =
  | "synthetic"
  | "claude"
  | "gpt-oss"
  | "openai"
  | "gemma"
  | "gemini"
  | "grok"
  | "llama"
  | "meta-ai"
  | "mistral"
  | "deepseek"
  | "qwen"
  | "kimi"
  | "glm"
  | "minimax"
  | "nemotron"
  | "microsoft"
  | "nova"
  | "cohere"
  | "sonar"
  | "stepfun"
  | "sakana"
  | "poolside"
  | "cursor"
  | "windsurf"
  | "doubao"
  | "hunyuan"
  | "ernie"
  | "yi"
  | "jamba"
  | "auto";

export type ModelFamily = {
  id: ModelFamilyId;
  /** Family name for tooltips, e.g. "Claude". */
  label: string;
  /** Who makes it, e.g. "Anthropic". */
  maker: string;
  /** Hidden families (synthetic) never render a mark. */
  hidden?: boolean;
};

const RULES: ReadonlyArray<readonly [RegExp, ModelFamily]> = [
  [new RegExp("^<synthetic"), { id: "synthetic", label: "Synthetic", maker: "Observer", hidden: true }],
  [new RegExp("claude|\\bopus\\b|\\bsonnet\\b|\\bhaiku\\b|fable"), { id: "claude", label: "Claude", maker: "Anthropic" }],
  [new RegExp("gpt-oss"), { id: "gpt-oss", label: "gpt-oss", maker: "OpenAI" }],
  [new RegExp("(^|[/:_-])(gpt|chatgpt|o[1-9](-|$)|codex|davinci|text-embedding|computer-use)"), { id: "openai", label: "GPT / o-series", maker: "OpenAI" }],
  [new RegExp("gemma"), { id: "gemma", label: "Gemma", maker: "Google" }],
  [new RegExp("gemini"), { id: "gemini", label: "Gemini", maker: "Google" }],
  [new RegExp("grok"), { id: "grok", label: "Grok", maker: "xAI" }],
  [new RegExp("llama"), { id: "llama", label: "Llama", maker: "Meta" }],
  [new RegExp("muse-|meta-ai|metaai"), { id: "meta-ai", label: "Muse / Meta AI", maker: "Meta" }],
  [new RegExp("mistral|mixtral|codestral|devstral|magistral|ministral|pixtral|voxtral"), { id: "mistral", label: "Mistral", maker: "Mistral AI" }],
  [new RegExp("deepseek"), { id: "deepseek", label: "DeepSeek", maker: "DeepSeek" }],
  [new RegExp("qwen|\\bqwq\\b|\\bqvq\\b"), { id: "qwen", label: "Qwen", maker: "Alibaba" }],
  [new RegExp("kimi|moonshot"), { id: "kimi", label: "Kimi", maker: "Moonshot AI" }],
  [new RegExp("(^|[/:_-])glm|chatglm|zhipu"), { id: "glm", label: "GLM", maker: "Z.ai" }],
  [new RegExp("minimax|abab"), { id: "minimax", label: "MiniMax", maker: "MiniMax" }],
  [new RegExp("nemotron"), { id: "nemotron", label: "Nemotron", maker: "NVIDIA" }],
  [new RegExp("(^|[/:_-])phi-?\\d|(^|[/:_-])mai-"), { id: "microsoft", label: "Phi / MAI", maker: "Microsoft" }],
  [new RegExp("(^|[/.:_-])nova-"), { id: "nova", label: "Nova", maker: "Amazon" }],
  [new RegExp("command-r|command-a|cohere|(^|[/:_-])aya"), { id: "cohere", label: "Command", maker: "Cohere" }],
  [new RegExp("sonar|pplx"), { id: "sonar", label: "Sonar", maker: "Perplexity" }],
  [new RegExp("stepfun|(^|[/:_-])step-\\d"), { id: "stepfun", label: "Step", maker: "StepFun" }],
  [new RegExp("sakana|fugu"), { id: "sakana", label: "Sakana", maker: "Sakana AI" }],
  [new RegExp("poolside|laguna|malibu"), { id: "poolside", label: "Laguna", maker: "Poolside" }],
  [new RegExp("composer-"), { id: "cursor", label: "Composer", maker: "Cursor" }],
  [new RegExp("(^|[/:_-])swe-\\d"), { id: "windsurf", label: "SWE", maker: "Windsurf / Cognition" }],
  [new RegExp("doubao|(^|[/:_-])seed-"), { id: "doubao", label: "Doubao / Seed", maker: "ByteDance" }],
  [new RegExp("hunyuan"), { id: "hunyuan", label: "Hunyuan", maker: "Tencent" }],
  [new RegExp("ernie|wenxin"), { id: "ernie", label: "ERNIE", maker: "Baidu" }],
  [new RegExp("(^|[/:_-])yi-"), { id: "yi", label: "Yi", maker: "01.AI" }],
  [new RegExp("jamba|ai21"), { id: "jamba", label: "Jamba", maker: "AI21" }],
  [new RegExp("(^|/)(auto|default|smart|turbo|free)(\\b|$)|-auto/|/auto$"), { id: "auto", label: "Auto-routed", maker: "router" }],
];

/** Resolve a raw model id to its family, or null when nothing matches. */
export function modelFamily(id: string | null | undefined): ModelFamily | null {
  if (!id) return null;
  const s = id.trim().toLowerCase();
  for (const [re, fam] of RULES) if (re.test(s)) return fam;
  return null;
}
