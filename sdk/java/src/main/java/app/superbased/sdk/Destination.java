package app.superbased.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Level;

/**
 * Where the SDK sends data: {@code local} (this machine), {@code online} (the
 * organization's gateway) or {@code both} (contract destination.md).
 * {@link #resolve} turns the settings, the environment and (when needed) the
 * machine's loopback discovery answer into a {@link Plan}: the export targets,
 * the admit() target and the control-API bases.
 */
final class Destination {
  static final String LOCAL = "local";
  static final String ONLINE = "online";
  static final String BOTH = "both";
  static final List<String> VALUES = List.of(LOCAL, ONLINE, BOTH);

  static final String DISCOVERY_PATH = "/api/sdk/destination";
  /** One attempt, fixed (contract section 4; review R-B19). */
  static final Duration DISCOVERY_TIMEOUT = Duration.ofMillis(500);

  static final String ADMISSION_PATH = "/api/obs/admission/check";
  static final String SDK_ADMIT_PATH = "/v1/sdk/admit";
  static final String CREDENTIAL_GATEWAY_FIELD = "gateway_url";

  private Destination() {}

  /** One OTLP/HTTP export target. */
  static final class Target {
    final String endpoint;
    final Map<String, String> headers; // may carry the credential: never logged
    final Duration timeout;
    final String name;

    Target(String endpoint, Map<String, String> headers, Duration timeout, String name) {
      this.endpoint = endpoint;
      this.headers = Collections.unmodifiableMap(new TreeMap<>(headers));
      this.timeout = timeout;
      this.name = name;
    }

    String key() {
      return name + "|" + endpoint + "|" + headers + "|" + timeout.toMillis();
    }
  }

  /** The resolved destination. */
  static final class Plan {
    String destination = LOCAL;
    String source = "default"; // argument | env | sdk_file | machine | inferred | default
    List<Target> exporters = List.of();
    String nodeUrl = Settings.DEFAULT_NODE_URL;
    String gatewayUrl = "";
    boolean onlineReady;
    String admitUrl = "";
    String machineAdmitUrl = "";
    String degraded = "";
    List<String> warnings = List.of();
    List<String> notes = List.of();
    Boolean signedIn;
    String credentialSource = ""; // argument | env | file | sdk_file | ""
    /** The online credential: never logged, never in diagnostics, never sent to the machine. */
    String key = "";
    /** Diagnostics' sdk_file: path, state (absent, used, unused, refused, expired, not_read) and reason. */
    Map<String, Object> sdkFile = Map.of("path", "", "state", SdkFile.NOT_READ, "reason", "");
    /** The organization's dashboard base for links (the SDK-held file's, or discovery's for the machine's key). */
    String onlineDashboard = "";
    /** The machine's dashboard base, known only when the machine answered discovery. */
    String localDashboard = "";

    Map<String, String> onlineHeaders() {
      return key.isEmpty() ? Map.of() : Map.of("Authorization", "Bearer " + key);
    }

    boolean onlineEnabled() {
      return (ONLINE.equals(destination) || BOTH.equals(destination)) && onlineReady;
    }

    Map<String, Object> summary() {
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("destination", destination);
      out.put("destination_source", source);
      List<Map<String, Object>> dests = new ArrayList<>();
      for (Target t : exporters) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("name", t.name);
        d.put("endpoint", t.endpoint);
        dests.add(d);
      }
      out.put("destinations", dests);
      out.put("gateway_url", gatewayUrl);
      out.put("degraded", degraded);
      out.put("warnings", new ArrayList<>(warnings));
      out.put("notes", new ArrayList<>(notes));
      out.put("signed_in", signedIn);
      out.put("credential_source", credentialSource);
      out.put("sdk_file", new LinkedHashMap<>(sdkFile));
      return out;
    }

    Plan withWarning(String w) {
      List<String> ws = new ArrayList<>(warnings);
      ws.add(w);
      warnings = Collections.unmodifiableList(ws);
      return this;
    }
  }

  /** A discovery answer: the body, or the reason there is none. */
  static final class Discovered {
    final Map<String, Object> body;
    final String error;

    Discovered(Map<String, Object> body, String error) {
      this.body = body;
      this.error = error;
    }
  }

  /** The discovery seam (tests replace it to stand in for a machine). */
  interface Discoverer {
    Discovered discover(String nodeUrl);
  }

  private static final Map<String, Discovered> CACHE = new HashMap<>();
  static volatile Discoverer discoverer = Destination::discoverOnce;

  /** The machine's discovery answer, cached per process; only a loopback node_url is asked. */
  static Discovered discover(String nodeUrl) {
    synchronized (CACHE) {
      Discovered d = CACHE.get(nodeUrl);
      if (d != null) {
        return d;
      }
    }
    Discovered d = discoverer.discover(nodeUrl);
    synchronized (CACHE) {
      CACHE.put(nodeUrl, d);
    }
    return d;
  }

  @SuppressWarnings("unchecked")
  static Discovered discoverOnce(String nodeUrl) {
    if (!Http.isLoopbackUrl(nodeUrl)) {
      return new Discovered(
          null, "SUPERBASED_NODE_URL " + nodeUrl + " is not a loopback address; destination discovery skipped");
    }
    Http.Response resp = Http.request("GET", Http.join(nodeUrl, DISCOVERY_PATH, null), null, null, DISCOVERY_TIMEOUT);
    if (resp.status != 200) {
      return new Discovered(null, "machine destination discovery failed: " + resp.describe());
    }
    Map<String, Object> body = resp.object();
    if (body == null || !Long.valueOf(1).equals(body.get("api_version"))) {
      return new Discovered(null, "machine destination discovery answered an unknown api_version");
    }
    return new Discovered(body, "");
  }

  // --- credential file -----------------------------------------------------------------

  /** (key, gateway, error) of a credential file; {@code raw} is the bytes an owner-only read gave. */
  static final class Credential {
    final String key;
    final String gateway;
    final String error;
    byte[] raw = new byte[0];
    /** The refused rule (credential-file-cases.json reasons), "" for an I/O error or none. */
    String reason = "";

    Credential(String key, String gateway, String error) {
      this.key = key;
      this.gateway = gateway;
      this.error = error;
    }
  }

  /**
   * Unix rules (contract section 6): no symlink, no group/other permission
   * bits, owned by this user. The first line is {@code <key_id>.<secret>};
   * each further line is {@code name=value}, where {@code gateway_url} names
   * the only address the key is sent to (review E-04). Unknown names are
   * ignored; a gateway that is not https (or http to this machine) is refused.
   */
  static Credential readCredentialRecord(String path) {
    if (path == null || path.isEmpty()) {
      return new Credential("", "", "");
    }
    if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
      return new Credential("", "", "credential files are not read on Windows; set SUPERBASED_API_KEY");
    }
    Credential c = readOwnerOnly(Path.of(path));
    if (!c.error.isEmpty()) {
      return c;
    }
    SdkFile.Record r = SdkFile.parse(c.raw);
    if (!r.problem.isEmpty()) {
      return new Credential("", "", r.problem);
    }
    return new Credential(r.key, r.gateway, r.gatewayIssue);
  }

  /**
   * At most 4097 bytes of {@code p} under contract section 6's unix rules: no
   * symlink, a regular file, no group or other permission bits, owned by
   * this user. The bytes are in {@code raw}; a refusal is {@code error}.
   */
  static Credential readOwnerOnly(Path p) {
    PosixFileAttributes st;
    try {
      st = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    } catch (IOException | UnsupportedOperationException e) {
      return refused("cannot read the SDK credential file: " + e.getMessage(), "");
    }
    if (st.isSymbolicLink()) {
      return refused("the SDK credential file is a symlink; refused", SdkFile.R_SYMLINK);
    }
    if (!st.isRegularFile()) {
      return refused("the SDK credential file is not a regular file; refused", SdkFile.R_NOT_REGULAR);
    }
    Set<PosixFilePermission> perms = st.permissions();
    for (PosixFilePermission bad :
        List.of(
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ,
            PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE)) {
      if (perms.contains(bad)) {
        return refused("the SDK credential file is readable by other users; refused (chmod 600)", SdkFile.R_MODE);
      }
    }
    if (!ownedByProcessUser(p, st)) {
      return refused("the SDK credential file is owned by another user; refused", SdkFile.R_OWNER);
    }
    byte[] raw;
    try (SeekableByteChannel ch = Files.newByteChannel(p, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
        InputStream in = Channels.newInputStream(ch)) {
      raw = in.readNBytes(SdkFile.LIMIT + 1);
    } catch (IOException e) {
      return refused("cannot read the SDK credential file: " + e.getMessage(), "");
    }
    Credential out = new Credential("", "", "");
    out.raw = raw;
    return out;
  }

  private static Credential refused(String error, String reason) {
    Credential c = new Credential("", "", error);
    c.reason = reason;
    return c;
  }

  /** The process's uid, or -1 when unknown. Tests replace it. */
  static volatile java.util.function.LongSupplier processUid = Destination::detectProcessUid;

  private static long detectProcessUid() {
    try {
      Object unix = Class.forName("com.sun.security.auth.module.UnixSystem").getDeclaredConstructor().newInstance();
      return ((Number) unix.getClass().getMethod("getUid").invoke(unix)).longValue();
    } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
      // fall through to /proc
    }
    try {
      Object uid = Files.getAttribute(Path.of("/proc/self"), "unix:uid");
      return ((Number) uid).longValue();
    } catch (IOException | RuntimeException e) {
      return -1;
    }
  }

  /**
   * Whether the file belongs to this process's user. By uid, not name: a
   * container running an arbitrary uid has no passwd entry, so its name never
   * matches the file's owner. Falls back to the name only when a uid cannot
   * be read.
   */
  private static boolean ownedByProcessUser(Path p, PosixFileAttributes st) {
    try {
      long mine = processUid.getAsLong();
      if (mine >= 0) {
        Object fileUid = Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        return ((Number) fileUid).longValue() == mine;
      }
    } catch (IOException | RuntimeException e) {
      // no uid: compare names below
    }
    String me = System.getProperty("user.name", "");
    return me.isEmpty() || st.owner().getName().equals(me);
  }

  /** "" when {@code url} is a usable gateway base: https (or http to loopback), a host, no user info, query, fragment or path. */
  static String gatewayProblem(String url) {
    URI u;
    try {
      u = URI.create(url);
    } catch (IllegalArgumentException e) {
      return "'" + url + "' is not a URL";
    }
    String scheme = u.getScheme() == null ? "" : u.getScheme();
    String host = u.getHost() == null ? "" : u.getHost();
    if (!(scheme.equals("http") || scheme.equals("https")) || host.isEmpty()) {
      return "'" + url + "' is not an http(s) address with a host";
    }
    if (u.getRawUserInfo() != null) {
      return "'" + url + "' carries a user name or password";
    }
    String path = u.getRawPath() == null ? "" : u.getRawPath();
    if (u.getRawQuery() != null || u.getRawFragment() != null || !(path.isEmpty() || path.equals("/"))) {
      return "'" + url + "' is not a base address";
    }
    if (!scheme.equals("https") && !Http.isLoopbackUrl(url)) {
      return "'" + url + "' is plain http to a remote host";
    }
    return "";
  }

  // --- resolution ------------------------------------------------------------------------

  private static String valid(String value, String origin, List<String> warnings) {
    String v = value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
    if (v.isEmpty()) {
      return "";
    }
    if (!VALUES.contains(v)) {
      warnings.add("destination '" + value + "' from " + origin + " is not local, online or both; ignored");
      return "";
    }
    return v;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> loopbackLocalInfo(Object local, List<String> warnings) {
    Map<String, Object> out = new LinkedHashMap<>(local instanceof Map ? (Map<String, Object>) local : Map.of());
    for (String k : List.of("otlp_traces_url", "admission_url")) {
      Object v = out.get(k);
      if (v instanceof String && !((String) v).isEmpty() && !Http.isLoopbackUrl((String) v)) {
        warnings.add("the machine's discovery answer names a non-loopback " + k + " (" + v + "); ignored");
        out.remove(k);
      }
    }
    return out;
  }

  /** Whether the app named the local destination's endpoint itself. */
  static boolean localEndpointNamed(String explicit, Map<String, String> env, String dest) {
    if ((explicit != null && !explicit.isEmpty()) || !Util.first(env.get("SUPERBASED_OTLP_ENDPOINT")).isEmpty()) {
      return true;
    }
    return LOCAL.equals(dest)
        && !Util.first(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), env.get("OTEL_EXPORTER_OTLP_ENDPOINT")).isEmpty();
  }

  /**
   * (endpoint, named): explicit > SUPERBASED_OTLP_ENDPOINT > (local only) the
   * standard OTEL_EXPORTER_OTLP_* > the machine's advertised receiver > the
   * built-in loopback receiver. {@code named} only for the first two.
   */
  private static Object[] localEndpoint(String explicit, Map<String, String> env, String dest, Map<String, Object> localInfo) {
    if (explicit != null && !explicit.isEmpty()) {
      return new Object[] {explicit, true};
    }
    String v = Util.first(env.get("SUPERBASED_OTLP_ENDPOINT"));
    if (!v.isEmpty()) {
      return new Object[] {v, true};
    }
    if (LOCAL.equals(dest)) {
      v = Util.first(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"));
      if (!v.isEmpty()) {
        return new Object[] {v, false};
      }
      String base = Util.first(env.get("OTEL_EXPORTER_OTLP_ENDPOINT"));
      if (!base.isEmpty()) {
        return new Object[] {Http.stripRight(base, '/') + Settings.TRACES_PATH, false};
      }
    }
    Object adv = localInfo.get("otlp_traces_url");
    if (adv instanceof String && !((String) adv).isEmpty()) {
      return new Object[] {adv, false};
    }
    return new Object[] {Settings.DEFAULT_ENDPOINT, false};
  }

  private static boolean hasAuthorization(Map<String, String> h) {
    for (String k : h.keySet()) {
      if (k.equalsIgnoreCase("authorization")) {
        return true;
      }
    }
    return false;
  }

  /**
   * The destination plan for {@code s} (contract sections 3, 5, 6, 7).
   *
   * @param explicitDestination init()'s destination option (null when unset)
   * @param explicitEndpoint init()'s endpoint option (null when unset)
   * @param explicitHeaders init()'s headers option (null when unset)
   * @param explicitApiKey whether the credential came from init()'s apiKey option
   */
  @SuppressWarnings("unchecked")
  static Plan resolve(
      Settings s,
      Map<String, String> env,
      String explicitDestination,
      String explicitEndpoint,
      Map<String, String> explicitHeaders,
      boolean explicitApiKey) {
    List<String> warnings = new ArrayList<>();
    List<String> notes = new ArrayList<>();
    String dest = valid(explicitDestination, "init(destination)", warnings);
    String source = dest.isEmpty() ? "" : "argument";
    if (dest.isEmpty()) {
      dest = valid(env.getOrDefault("SUPERBASED_DESTINATION", ""), "SUPERBASED_DESTINATION", warnings);
      source = dest.isEmpty() ? "" : "env";
    }
    SdkFile.PlanReader held = new SdkFile.PlanReader(env, java.time.Instant.now());
    if (dest.isEmpty()) {
      dest = held.destination(warnings);
      source = dest.isEmpty() ? "" : SdkFile.SOURCE;
    }
    String nodeUrl = Http.stripRight(s.nodeUrl, '/');
    if (nodeUrl.isEmpty()) {
      nodeUrl = Settings.DEFAULT_NODE_URL;
    }
    String gateway = Util.first(s.orgUrl);
    String key = "";
    String keySource = "";
    if (!s.apiKey.isEmpty()) {
      key = s.apiKey;
      keySource = explicitApiKey ? "argument" : "env";
    }

    boolean needMachine =
        dest.isEmpty()
            || ((ONLINE.equals(dest) || BOTH.equals(dest)) && (gateway.isEmpty() || key.isEmpty()))
            || ((LOCAL.equals(dest) || BOTH.equals(dest)) && !localEndpointNamed(explicitEndpoint, env, dest));
    Map<String, Object> found = null;
    if (needMachine && s.discover) {
      Discovered d = discover(nodeUrl);
      found = d.body;
      if (!d.error.isEmpty()) {
        notes.add(d.error);
      }
    }
    Boolean signedIn = null;
    Map<String, Object> localInfo = Map.of();
    boolean machineRecord = false;
    String onlineDashboard = "";
    String localDashboard = "";
    if (found != null) {
      localDashboard = nodeUrl;
      signedIn = Boolean.TRUE.equals(found.get("signed_in"));
      localInfo = loopbackLocalInfo(found.get("local"), warnings);
      Map<String, Object> online = found.get("online") instanceof Map ? (Map<String, Object>) found.get("online") : Map.of();
      Object ws = found.get("warnings");
      if (ws instanceof List) {
        for (Object w : (List<Object>) ws) {
          if (w instanceof String && !((String) w).isEmpty()) {
            warnings.add("machine: " + w);
          }
        }
      }
      if (dest.isEmpty()) {
        Object fd = found.get("destination");
        dest = valid(fd == null ? "" : String.valueOf(fd), "the machine", warnings);
        source = dest.isEmpty() ? "" : "machine";
      }
      if (!LOCAL.equals(dest)
          && (key.isEmpty() || gateway.isEmpty())
          && Boolean.TRUE.equals(online.get("credential_present"))
          && online.get("credential_file") instanceof String) {
        Credential c = readCredentialRecord((String) online.get("credential_file"));
        machineRecord = !c.key.isEmpty();
        if (key.isEmpty() && !c.key.isEmpty()) {
          key = c.key;
          keySource = "file";
          onlineDashboard = SdkFile.discoveredDashboard(online);
        }
        if (gateway.isEmpty()) {
          gateway = c.gateway;
        }
        if (!c.error.isEmpty()) {
          warnings.add(c.error);
        }
      }
    }
    if (dest.isEmpty() && found == null && !gateway.isEmpty() && !key.isEmpty()) {
      dest = ONLINE;
      source = "inferred";
    }
    if (dest.isEmpty()) {
      dest = LOCAL;
      source = "default";
    }
    if (ONLINE.equals(dest) || BOTH.equals(dest)) {
      // Record 3, the SDK-held file, once the destination is known: it never
      // makes the inferred rung (that is argument or env only).
      SdkFile.Applied a = SdkFile.apply(held, machineRecord, "file".equals(keySource), key, keySource, gateway, onlineDashboard);
      key = a.key;
      keySource = a.keySource;
      gateway = a.gateway;
      onlineDashboard = a.dashboard;
      warnings.addAll(a.warnings);
    }

    boolean onlineReady = !gateway.isEmpty() && !key.isEmpty();
    String degraded = "";
    if ((ONLINE.equals(dest) || BOTH.equals(dest)) && !onlineReady) {
      List<String> missing = new ArrayList<>();
      if (gateway.isEmpty()) {
        missing.add("the gateway address");
      }
      if (key.isEmpty()) {
        missing.add("an SDK credential");
      }
      String fix = held.degradedFix(source, keySource);
      degraded =
          ONLINE.equals(dest)
              ? "destination online is missing " + String.join(" and ", missing) + ": nothing is exported (" + fix + ")"
              : "destination both is missing " + String.join(" and ", missing) + ": exporting to this machine only (" + fix + ")";
    }
    if (Boolean.FALSE.equals(localInfo.get("enabled")) && (LOCAL.equals(dest) || BOTH.equals(dest))) {
      warnings.add(
          "observability is off on this machine, so it refuses local spans (turn it on in the dashboard Settings)");
    }

    List<Target> exporters = new ArrayList<>();
    if (LOCAL.equals(dest) || BOTH.equals(dest)) {
      Object[] le = localEndpoint(explicitEndpoint, env, dest, localInfo);
      String endpoint = (String) le[0];
      boolean named = (Boolean) le[1];
      Map<String, String> hdrs = new LinkedHashMap<>();
      if (LOCAL.equals(dest)) {
        for (String n : List.of("OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS")) {
          hdrs.putAll(Util.parseKvList(env.get(n)));
        }
      }
      hdrs.putAll(Util.parseKvList(env.get("SUPERBASED_OTLP_HEADERS")));
      if (explicitHeaders != null) {
        hdrs.putAll(explicitHeaders);
      }
      // The credential never goes to the machine, and never to an endpoint
      // from OTEL_EXPORTER_OTLP_*: only a remote collector the app named for
      // superbased itself carries it.
      if (!s.apiKey.isEmpty() && named && !Http.isLoopbackUrl(endpoint) && !hasAuthorization(hdrs)) {
        hdrs.put("Authorization", "Bearer " + s.apiKey);
      }
      exporters.add(new Target(endpoint, hdrs, s.exportTimeout, LOCAL));
    }
    if ((ONLINE.equals(dest) || BOTH.equals(dest)) && onlineReady) {
      Map<String, String> hdrs = new LinkedHashMap<>(Util.parseKvList(env.get("SUPERBASED_OTLP_HEADERS")));
      if (explicitHeaders != null) {
        hdrs.putAll(explicitHeaders);
      }
      hdrs.keySet().removeIf(k -> k.equalsIgnoreCase("authorization")); // the SDK credential always wins
      hdrs.put("Authorization", "Bearer " + key);
      exporters.add(new Target(Http.stripRight(gateway, '/') + Settings.TRACES_PATH, hdrs, s.exportTimeout, ONLINE));
    }

    Object adm = localInfo.get("admission_url");
    String machineAdmitUrl = adm instanceof String && !((String) adm).isEmpty() ? (String) adm : nodeUrl + ADMISSION_PATH;
    Plan p = new Plan();
    p.destination = dest;
    p.source = source;
    p.exporters = Collections.unmodifiableList(exporters);
    p.nodeUrl = nodeUrl;
    p.gatewayUrl = Http.stripRight(gateway, '/');
    p.onlineReady = onlineReady;
    p.admitUrl =
        (ONLINE.equals(dest) || BOTH.equals(dest)) && onlineReady
            ? Http.stripRight(gateway, '/') + SDK_ADMIT_PATH
            : machineAdmitUrl;
    p.machineAdmitUrl = machineAdmitUrl;
    p.degraded = degraded;
    p.warnings = Collections.unmodifiableList(warnings);
    p.notes = Collections.unmodifiableList(notes);
    p.signedIn = signedIn;
    p.credentialSource = keySource;
    p.key = key;
    p.sdkFile = held.info(keySource);
    p.onlineDashboard = onlineDashboard;
    p.localDashboard = localDashboard;
    return p;
  }

  private static final Set<String> LOGGED = new HashSet<>();

  /** Each degraded reason and warning (WARNING) and note (INFO), once per process. */
  static void logOnce(Plan plan) {
    List<Object[]> rows = new ArrayList<>();
    if (!plan.degraded.isEmpty()) {
      rows.add(new Object[] {Level.WARNING, plan.degraded});
    }
    for (String w : plan.warnings) {
      rows.add(new Object[] {Level.WARNING, w});
    }
    for (String n : plan.notes) {
      rows.add(new Object[] {Level.INFO, n});
    }
    for (Object[] r : rows) {
      synchronized (LOGGED) {
        if (!LOGGED.add((String) r[1])) {
          continue;
        }
      }
      Util.LOG.log((Level) r[0], "superbased_sdk: " + r[1]);
    }
  }

  /** Forget the discovery cache only (tests). */
  static void resetCacheForTests() {
    synchronized (CACHE) {
      CACHE.clear();
    }
  }

  static void resetForTests() {
    synchronized (CACHE) {
      CACHE.clear();
    }
    synchronized (LOGGED) {
      LOGGED.clear();
    }
    discoverer = Destination::discoverOnce;
  }
}
