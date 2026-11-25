package app.superbased.sdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code getPrompt()} (contract prompts.md): fetches a prompt version from the
 * registry of the destination, caches it per (endpoint, name, selector, side)
 * for the cache TTL, then serves the cached copy while ONE background thread
 * per key revalidates it with {@code If-None-Match} (stale-while-revalidate).
 */
final class Prompts {
  static final List<String> LABELS = List.of("production", "staging");
  static final String DEFAULT_LABEL = "production";
  private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$");
  private static final Set<String> NOT_FOUND =
      Set.of("prompt_not_found", "version_not_found", "label_not_set", "not_implemented");
  static final String SIDE_ALL = "all";
  static final List<String> SIDES_WITH_ROLLOUT = List.of("candidate", "base", "unkeyed");

  private Prompts() {}

  // --- parsing ------------------------------------------------------------------------------

  @SuppressWarnings("unchecked")
  static Prompt parse(Object body, String side, String label) {
    if (!(body instanceof Map)) {
      throw new PromptException.FetchFailed("the registry answered without a JSON object");
    }
    Map<String, Object> b = (Map<String, Object>) body;
    Object name = b.get("name");
    Object version = b.get("version");
    Object typ = b.get("type");
    Object prompt = b.get("prompt");
    boolean ok = name instanceof String && version instanceof Long;
    boolean chatOk = false;
    if ("chat".equals(typ) && prompt instanceof List) {
      chatOk = true;
      for (Object m : (List<Object>) prompt) {
        if (!(m instanceof Map)) {
          chatOk = false;
        }
      }
    }
    ok = ok && (("text".equals(typ) && prompt instanceof String) || chatOk);
    if (!ok) {
      throw new PromptException.FetchFailed("the registry answered with a malformed prompt");
    }
    List<String> variables = new ArrayList<>();
    if (b.get("variables") instanceof List) {
      for (Object v : (List<Object>) b.get("variables")) {
        variables.add(String.valueOf(v));
      }
    } else {
      variables = Prompt.placeholders(prompt instanceof String ? (String) prompt : Json.write(prompt));
    }
    List<String> labels = new ArrayList<>();
    if (b.get("labels") instanceof List) {
      for (Object l : (List<Object>) b.get("labels")) {
        if (l instanceof String) {
          labels.add((String) l);
        }
      }
    }
    Object cfg = b.get("config");
    return new Prompt(
        (String) name,
        (Long) version,
        (String) typ,
        Json.copy(prompt),
        cfg instanceof Map ? (Map<String, Object>) Json.copy(cfg) : new LinkedHashMap<>(),
        labels,
        label,
        str(b.get("resolved_by")),
        variables,
        str(b.get("digest")),
        str(b.get("commit_message")),
        str(b.get("created_at")),
        false,
        side,
        parseRollout(b.get("rollout")));
  }

  private static String str(Object v) {
    return v == null ? "" : String.valueOf(v);
  }

  private static long num(Object v) {
    return v instanceof Number ? ((Number) v).longValue() : 0;
  }

  @SuppressWarnings("unchecked")
  static PromptRollout parseRollout(Object ro) {
    if (!(ro instanceof Map)) {
      return null;
    }
    Map<String, Object> r = (Map<String, Object>) ro;
    if (!(r.get("salt") instanceof String) || !SIDES_WITH_ROLLOUT.contains(r.get("cohort"))) {
      return null;
    }
    return new PromptRollout(
        num(r.get("base_version")),
        num(r.get("candidate_version")),
        (int) num(r.get("percent")),
        (String) r.get("cohort"),
        str(r.get("key")),
        (String) r.get("salt"));
  }

  // --- prompts.md v2: the cohort key and the rollout bucket (section 9.2) ------------------

  /** Lowercase hex SHA-256 of {@code value}'s UTF-8 bytes (what is sent as user_hash / session_hash). */
  static String cohortHash(String value) {
    return Util.hex(Util.sha256(value));
  }

  /** {@code uint32_be(sha256(salt + "|" + subject)[0:4]) % 100}. */
  static int rolloutBucket(String salt, String subject) {
    byte[] d = Util.sha256(salt + "|" + subject);
    long v = ((d[0] & 0xffL) << 24) | ((d[1] & 0xffL) << 16) | ((d[2] & 0xffL) << 8) | (d[3] & 0xffL);
    return (int) (v % 100);
  }

  /** The key a label fetch is bucketed by. */
  static final class Cohort {
    final String subject;
    final Map<String, String> query;

    Cohort(String subject, Map<String, String> query) {
      this.subject = subject;
      this.query = query;
    }
  }

  static Cohort cohortOf(String selector, String user, String sessionId) {
    if (selector.startsWith("version:")) {
      return new Cohort("", Map.of());
    }
    Map<String, Object> cur = AttributeContext.current(null).publicView();
    String u = user != null ? user : str(cur.getOrDefault("user", ""));
    if (!u.isEmpty()) {
      String h = cohortHash(u);
      return new Cohort("user:" + h, Map.of("user_hash", h));
    }
    String s = sessionId != null ? sessionId : str(cur.getOrDefault("session_id", ""));
    if (!s.isEmpty()) {
      String h = cohortHash(s);
      return new Cohort("session:" + h, Map.of("session_hash", h));
    }
    return new Cohort("", Map.of());
  }

  static String sideOf(Prompt p) {
    return p.rollout != null ? p.rollout.cohort() : SIDE_ALL;
  }

  // --- the cache ----------------------------------------------------------------------------

  static final class Entry {
    final Prompt prompt;
    final String etag;
    volatile long fetchedNanos;
    volatile boolean refreshing;
    final Map<String, String> query;

    Entry(Prompt prompt, String etag, Map<String, String> query) {
      this.prompt = prompt;
      this.etag = etag;
      this.fetchedNanos = System.nanoTime();
      this.query = query;
    }
  }

  /** (endpoint, name, selector) and the side. */
  static String groupKey(String endpoint, String name, String selector) {
    return endpoint + "\u0000" + name + "\u0000" + selector;
  }

  static final class Cache {
    private final Map<String, Map<String, Entry>> groups = new HashMap<>();
    private long lastLog;

    synchronized void clear() {
      groups.clear();
    }

    synchronized Entry get(String group, String side) {
      Map<String, Entry> g = groups.get(group);
      return g == null ? null : g.get(side);
    }

    synchronized void drop(String group, String side) {
      Map<String, Entry> g = groups.get(group);
      if (g != null) {
        g.remove(side);
      }
    }

    /** The side {@code cohort} is served from: bucket with a cached rollout's salt and percent, else all. */
    synchronized String sideFor(String group, Cohort cohort) {
      PromptRollout ro = null;
      Map<String, Entry> g = groups.get(group);
      if (g != null) {
        for (Entry e : g.values()) {
          if (e.prompt.rollout != null) {
            ro = e.prompt.rollout;
            break;
          }
        }
      }
      if (ro == null) {
        return SIDE_ALL;
      }
      if (cohort.subject.isEmpty()) {
        return "unkeyed";
      }
      return rolloutBucket(ro.salt(), cohort.subject) < ro.percent() ? "candidate" : "base";
    }

    /** Keep an answer under the side it names; a changed rollout drops the other sides. */
    synchronized void store(String group, Prompt p, String etag, Map<String, String> query) {
      String sig = p.rollout != null ? p.rollout.signature() : "";
      Map<String, Entry> g = groups.computeIfAbsent(group, k -> new LinkedHashMap<>());
      g.entrySet()
          .removeIf(
              e -> !(e.getValue().prompt.rollout != null ? e.getValue().prompt.rollout.signature() : "").equals(sig));
      g.put(sideOf(p), new Entry(p, etag, query));
    }

    /** The cached sides of every group of prompt {@code name}, sorted (tests). */
    synchronized List<String> sidesOf(String name) {
      List<String> out = new ArrayList<>();
      for (Map.Entry<String, Map<String, Entry>> g : groups.entrySet()) {
        if (g.getKey().contains("\u0000" + name + "\u0000")) {
          out.addAll(g.getValue().keySet());
        }
      }
      out.sort(null);
      return out;
    }

    synchronized boolean claimRefresh(String group, String side) {
      Entry e = get(group, side);
      if (e == null || e.refreshing) {
        return false;
      }
      e.refreshing = true;
      return true;
    }

    void logFailure(String msg) {
      long now = System.currentTimeMillis();
      synchronized (this) {
        if (now - lastLog < 60_000) {
          return;
        }
        lastLog = now;
      }
      Util.warn("prompt revalidation failed, serving the cached copy: " + msg);
    }
  }

  static final Cache CACHE = new Cache();

  // --- fetching -----------------------------------------------------------------------------

  /** {selector, label stamped} plus the query. */
  private static Object[] selector(String label, Long version) {
    if (label != null && version != null) {
      throw new IllegalArgumentException("getPrompt takes a label or a version, not both");
    }
    if (version != null) {
      if (version < 1) {
        throw new IllegalArgumentException("version must be a positive integer, got " + version);
      }
      return new Object[] {"version:" + version, Map.of("version", version), ""};
    }
    String lbl = label != null && !label.isEmpty() ? label : DEFAULT_LABEL;
    if (!LABELS.contains(lbl)) {
      throw new IllegalArgumentException("label must be one of production, staging, got '" + lbl + "'");
    }
    return new Object[] {"label:" + lbl, Map.of("label", lbl), lbl};
  }

  private static Http.Response fetch(Control.Side side, String name, Map<String, Object> query, String etag) {
    Map<String, String> headers = etag.isEmpty() ? null : Map.of("If-None-Match", etag);
    return side.call("GET", "prompt", null, query, headers, Map.of("name", name));
  }

  private static boolean notFound(Http.Response r) {
    return (r.status == 404 || r.status == 501) && (NOT_FOUND.contains(r.errorCode()) || r.errorCode().isEmpty());
  }

  private static Map<String, Object> merged(Map<String, Object> a, Map<String, String> b) {
    Map<String, Object> out = new LinkedHashMap<>(a);
    out.putAll(b);
    return out;
  }

  private static void revalidate(String group, String side, Control.Side s, String name, Map<String, Object> query, String label) {
    Entry entry = CACHE.get(group, side);
    try {
      if (entry == null) {
        return;
      }
      Http.Response resp = fetch(s, name, merged(query, entry.query), entry.etag);
      if (resp.status == 304) {
        entry.fetchedNanos = System.nanoTime();
      } else if (resp.status == 200) {
        Prompt p = parse(resp.body, s.name, label);
        if (!sideOf(p).equals(side)) {
          CACHE.drop(group, side);
        }
        CACHE.store(group, p, resp.header("etag"), entry.query);
        return;
      } else if (notFound(resp)) {
        CACHE.drop(group, side);
        return;
      } else {
        CACHE.logFailure(resp.describe());
      }
    } catch (RuntimeException e) {
      CACHE.logFailure(e.toString());
    } finally {
      Entry e = CACHE.get(group, side);
      if (e != null) {
        e.refreshing = false;
      }
    }
  }

  @SuppressWarnings("unchecked")
  static Prompt getPrompt(String name, PromptOptions o) {
    PromptOptions opts = o == null ? PromptOptions.defaults() : o;
    if (name == null || !NAME.matcher(name).matches()) {
      throw new IllegalArgumentException("prompt name '" + name + "' must match " + NAME.pattern());
    }
    Object[] sel = selector(opts.label, opts.version);
    String selector = (String) sel[0];
    Map<String, Object> query = new LinkedHashMap<>((Map<String, Object>) sel[1]);
    String stampedLabel = (String) sel[2];
    Cohort cohort = cohortOf(selector, opts.user, opts.sessionId);
    Duration ttl = opts.cacheTtl;
    if (ttl == null) {
      Settings s = Superbased.settings();
      ttl = s != null ? s.promptCacheTtl : Settings.DEFAULT_PROMPT_CACHE_TTL;
    }
    List<String> errors = new ArrayList<>();
    boolean nf = true;
    PlanRefusalException refused = null;
    List<Control.Side> targets = Control.sides();
    if (targets.isEmpty()) {
      errors.add(Control.unavailableReason());
      nf = false;
    }
    for (Control.Side side : targets) {
      String group = groupKey(side.name + ":" + side.base, name, selector);
      String key = CACHE.sideFor(group, cohort);
      Entry entry = CACHE.get(group, key);
      if (entry != null) {
        if (System.nanoTime() - entry.fetchedNanos >= Math.max(0, ttl.toNanos()) && CACHE.claimRefresh(group, key)) {
          Thread t =
              new Thread(() -> revalidate(group, key, side, name, query, stampedLabel), "superbased-prompt-refresh");
          t.setDaemon(true);
          t.start();
        }
        entry.prompt.stamp(null);
        return entry.prompt;
      }
      Http.Response resp;
      try {
        resp = fetch(side, name, merged(query, cohort.query), "");
      } catch (RuntimeException e) {
        errors.add(side.name + ": " + e);
        nf = false;
        continue;
      }
      if (resp.status == 200) {
        Prompt p;
        try {
          p = parse(resp.body, side.name, stampedLabel);
        } catch (PromptException.FetchFailed e) {
          errors.add(side.name + ": " + e.getMessage());
          nf = false;
          continue;
        }
        CACHE.store(group, p, resp.header("etag"), cohort.query);
        p.stamp(null);
        return p;
      }
      if (notFound(resp)) {
        String msg = resp.status == 501 || resp.errorCode().isEmpty() ? "this server has no prompt registry" : resp.describe();
        errors.add(side.name + ": " + msg);
        continue;
      }
      nf = false;
      if (refused == null) {
        refused = resp.planRefusal();
      }
      errors.add(side.name + ": " + resp.describe());
    }
    if (opts.fallback != null) {
      return fallback(name, opts.fallback);
    }
    String detail = errors.isEmpty() ? "no destination" : String.join("; ", errors);
    if (nf) {
      throw new PromptException.NotFound("prompt '" + name + "' (" + selector + ") not found: " + detail);
    }
    // When the org's plan refused it, the refusal is the cause (and planRefusal()).
    throw new PromptException.FetchFailed("prompt '" + name + "' (" + selector + ") could not be fetched: " + detail, refused);
  }

  @SuppressWarnings("unchecked")
  private static Prompt fallback(String name, Object body) {
    if (body instanceof List) {
      List<Map<String, Object>> msgs = new ArrayList<>();
      for (Object m : (List<Object>) body) {
        msgs.add(new LinkedHashMap<>((Map<String, Object>) m));
      }
      return new Prompt(
          name, 0, "chat", msgs, null, null, "", "", Prompt.placeholders(Json.write(body)), "", "", "", true, "fallback", null);
    }
    String text = String.valueOf(body);
    return new Prompt(name, 0, "text", text, null, null, "", "", Prompt.placeholders(text), "", "", "", true, "fallback", null);
  }
}
