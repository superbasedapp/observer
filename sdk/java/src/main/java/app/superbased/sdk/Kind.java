package app.superbased.sdk;

/**
 * The OpenInference span kinds ({@code openinference.span.kind}), uppercase.
 * Pass one to {@link Superbased#span(String)}'s {@code kind(...)}.
 */
public final class Kind {
  public static final String LLM = "LLM";
  public static final String TOOL = "TOOL";
  public static final String RETRIEVER = "RETRIEVER";
  public static final String EMBEDDING = "EMBEDDING";
  public static final String CHAIN = "CHAIN";
  public static final String AGENT = "AGENT";
  public static final String GUARDRAIL = "GUARDRAIL";
  public static final String EVALUATOR = "EVALUATOR";

  private Kind() {}
}
