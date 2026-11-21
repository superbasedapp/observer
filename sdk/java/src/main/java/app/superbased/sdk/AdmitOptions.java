package app.superbased.sdk;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The options of {@link Superbased#admit(String, AdmitOptions)}. Every value
 * is optional: identity defaults to the request scope, then init()'s; the
 * address to the plan of init() (contract destination.md section 8).
 */
public final class AdmitOptions {
  final String tenant;
  final String user;
  final String session;
  final String traceId;
  final String requestId;
  final String endpoint;
  final String orgUrl;
  final String apiKey;
  final Map<String, String> headers;
  final Duration timeout;
  final Boolean failClosed;

  private AdmitOptions(Builder b) {
    tenant = b.tenant;
    user = b.user;
    session = b.session;
    traceId = b.traceId;
    requestId = b.requestId;
    endpoint = b.endpoint;
    orgUrl = b.orgUrl;
    apiKey = b.apiKey;
    headers = b.headers == null ? null : Map.copyOf(b.headers);
    timeout = b.timeout;
    failClosed = b.failClosed;
  }

  public static AdmitOptions defaults() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link AdmitOptions}. */
  public static final class Builder {
    private String tenant;
    private String user;
    private String session;
    private String traceId;
    private String requestId;
    private String endpoint;
    private String orgUrl;
    private String apiKey;
    private Map<String, String> headers;
    private Duration timeout;
    private Boolean failClosed;

    private Builder() {}

    public Builder tenant(String v) {
      tenant = v;
      return this;
    }

    public Builder user(String v) {
      user = v;
      return this;
    }

    public Builder session(String v) {
      session = v;
      return this;
    }

    public Builder traceId(String v) {
      traceId = v;
      return this;
    }

    public Builder requestId(String v) {
      requestId = v;
      return this;
    }

    /** A full admission URL (wins over everything else). */
    public Builder endpoint(String v) {
      endpoint = v;
      return this;
    }

    /** An organization gateway base: {@code <org>/v1/sdk/admit}. */
    public Builder orgUrl(String v) {
      orgUrl = v;
      return this;
    }

    /** An explicit credential (the only one ever sent to a loopback endpoint). */
    public Builder apiKey(String v) {
      apiKey = v;
      return this;
    }

    /** Headers added to (or overriding) the request's. */
    public Builder headers(Map<String, String> v) {
      headers = v == null ? null : new LinkedHashMap<>(v);
      return this;
    }

    /** Default: the server's advertised recommended timeout once seen, else 12 s. */
    public Builder timeout(Duration v) {
      timeout = v;
      return this;
    }

    /** Deny when no decision could be obtained ({@code SUPERBASED_ADMISSION_FAIL_CLOSED}). */
    public Builder failClosed(boolean v) {
      failClosed = v;
      return this;
    }

    public AdmitOptions build() {
      return new AdmitOptions(this);
    }
  }
}
