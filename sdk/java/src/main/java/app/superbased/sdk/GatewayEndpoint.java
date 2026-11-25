package app.superbased.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Where a model client sends its calls through the organization's AI gateway
 * ({@link Gateway#endpoint}): the base URL to give the client, where it came
 * from, and the {@code X-SBO-Upstream} header it must send when the address
 * names no upstream. Build request URLs with {@link #url} and headers with
 * {@link #headers()}.
 */
public final class GatewayEndpoint {
  private final String baseUrl;
  private final String source;
  private final String upstream;
  private final String upstreamHeader;

  GatewayEndpoint(String baseUrl, String source, String upstream, String upstreamHeader) {
    this.baseUrl = baseUrl;
    this.source = source;
    this.upstream = upstream;
    this.upstreamHeader = upstreamHeader;
  }

  /** The client's base URL option. */
  public String baseUrl() {
    return baseUrl;
  }

  /** Where it came from: {@code argument}, {@code env}, {@code org} or {@code machine}. */
  public String source() {
    return source;
  }

  /** The upstream id ("" when the address names none). */
  public String upstream() {
    return upstream;
  }

  /**
   * The {@code X-SBO-Upstream} value the client must send: the upstream you
   * named with an explicit or environment address, which carries none in its
   * path. "" otherwise.
   */
  public String upstreamHeader() {
    return upstreamHeader;
  }

  /**
   * The request URL for {@code path}, the provider's path after the base URL
   * (for example {@code chat/completions} on an OpenAI base, or
   * {@code v1/messages} on an Anthropic one).
   */
  public String url(String path) {
    String p = path == null ? "" : path.strip();
    while (p.startsWith("/")) {
      p = p.substring(1);
    }
    return p.isEmpty() ? baseUrl : baseUrl + "/" + p;
  }

  /**
   * The headers a request through this endpoint carries now:
   * {@link Gateway#headers()} (the app identity, a request id and the current
   * span's {@code traceparent}) plus {@code X-SBO-Upstream} when it is needed.
   * The key is not among them: see {@link #apiKey()}. Never throws.
   */
  public Map<String, String> headers() {
    Map<String, String> out = new LinkedHashMap<>(Gateway.headers());
    if (!upstreamHeader.isEmpty()) {
      out.put(Gateway.UPSTREAM_HEADER, upstreamHeader);
    }
    return out;
  }

  /**
   * The key the client sends: {@code SUPERBASED_AI_GATEWAY_KEY}; null on this
   * machine's app lane (the client sends the provider's own key, which the lane
   * forwards) and on a loopback address with no gateway key set. A remote
   * gateway with no gateway key throws, so the provider's key is never sent
   * there.
   *
   * @throws Gateway.NotConfiguredException with problem {@code no_key}
   */
  public String apiKey() {
    if (Gateway.SOURCE_MACHINE.equals(source)) {
      return null;
    }
    String key = Gateway.key();
    if (!key.isEmpty()) {
      return key;
    }
    if (Http.isLoopbackUrl(baseUrl)) {
      return null;
    }
    throw new Gateway.NotConfiguredException(
        Gateway.PROBLEM_NO_KEY, "no AI gateway key for " + baseUrl + ": set " + Gateway.KEY_ENV);
  }

  @Override
  public String toString() {
    return "GatewayEndpoint{baseUrl=" + baseUrl + ", source=" + source + ", upstream=" + upstream + ", upstreamHeader=" + upstreamHeader + "}";
  }
}
