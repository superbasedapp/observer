package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Per-request identity for {@link Superbased#propagateAttributes} and
 * {@link Superbased#identify}: the end user, session, tenant, tags,
 * metadata, release and environment. An unset value keeps the outer scope's;
 * an empty string clears it for the inner scope.
 *
 * <pre>{@code
 * try (AttributeScope s = Superbased.propagateAttributes(
 *     TraceAttributes.builder().user("alice").sessionId("s1").build())) {
 *   ...
 * }
 * }</pre>
 */
public final class TraceAttributes {
  final String user;
  final String sessionId;
  final String tenant;
  final Object tags; // a collection or a comma-separated string
  final Map<String, Object> metadata;
  final String release;
  final String environment;
  final boolean asBaggage;

  private TraceAttributes(Builder b) {
    user = b.user;
    sessionId = b.sessionId;
    tenant = b.tenant;
    tags = b.tags;
    metadata = b.metadata;
    release = b.release;
    environment = b.environment;
    asBaggage = b.asBaggage;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link TraceAttributes}. */
  public static final class Builder {
    private String user;
    private String sessionId;
    private String tenant;
    private Object tags;
    private Map<String, Object> metadata;
    private String release;
    private String environment;
    private boolean asBaggage;

    private Builder() {}

    /** The app's end user ({@code sbo.user}; PII). */
    public Builder user(String v) {
      user = v;
      return this;
    }

    /** The conversation or session ({@code session.id}). */
    public Builder sessionId(String v) {
      sessionId = v;
      return this;
    }

    /** The customer tenant ({@code sbo.tenant}). */
    public Builder tenant(String v) {
      tenant = v;
      return this;
    }

    /** Tags, unioned with the outer scope's ({@code sbo.tags}). */
    public Builder tags(Collection<String> v) {
      tags = v == null ? null : new ArrayList<>(v);
      return this;
    }

    /** Tags as one comma-separated string. */
    public Builder tags(String commaList) {
      tags = commaList;
      return this;
    }

    /**
     * Metadata merged per key over the outer scope's ({@code sbo.metadata.<key>});
     * a null value deletes the key; a non-string value is JSON-encoded.
     */
    public Builder metadata(Map<String, ?> v) {
      metadata = v == null ? null : new LinkedHashMap<>(v);
      return this;
    }

    /** {@code sbo.release}. */
    public Builder release(String v) {
      release = v;
      return this;
    }

    /** {@code sbo.environment}. */
    public Builder environment(String v) {
      environment = v;
      return this;
    }

    /**
     * Also put the values into W3C baggage, so {@link Superbased#inject} carries
     * them to downstream services. Only for values you may send to them.
     */
    public Builder asBaggage(boolean v) {
      asBaggage = v;
      return this;
    }

    public TraceAttributes build() {
      return new TraceAttributes(this);
    }
  }

  List<Object[]> scalars() {
    List<Object[]> out = new ArrayList<>();
    out.add(new Object[] {"user", user});
    out.add(new Object[] {"session_id", sessionId});
    out.add(new Object[] {"tenant", tenant});
    out.add(new Object[] {"release", release});
    out.add(new Object[] {"environment", environment});
    return out;
  }
}
