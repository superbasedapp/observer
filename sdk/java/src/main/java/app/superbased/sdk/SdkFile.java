package app.superbased.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The SDK-held credential file (SDK quickstart plan section 3.4, contract
 * destination.md section 6a; cases {@code sdk/contract/credential-file-cases.json}):
 * an owner-only file outside the project, written only by {@code npx
 * @superbased/sdk setup} or {@code uvx superbased-sdk setup} (a Java app gets
 * its key with {@code setup --key-only}), read by every SDK. The runtime SDK
 * never writes it.
 *
 * <p>Path, first set wins: {@code SUPERBASED_CREDENTIAL_FILE} (not blank); on
 * Windows {@code %LOCALAPPDATA%\superbased\sdk-credential} (no LOCALAPPDATA:
 * no default path); elsewhere {@code $XDG_CONFIG_HOME/superbased/sdk-credential}
 * (an absolute XDG_CONFIG_HOME only), else {@code ~/.config/superbased/sdk-credential}.
 */
final class SdkFile {
  /** Replaces the SDK-held file's path. */
  static final String ENV_CREDENTIAL_FILE = "SUPERBASED_CREDENTIAL_FILE";

  static final String DIR = "superbased";
  static final String NAME = "sdk-credential";
  static final int LIMIT = 4096;
  static final Duration EXPIRY_WARNING = Duration.ofDays(14);

  /** The destination source (rung 3) and the credential source (record 3) the file gives. */
  static final String SOURCE = "sdk_file";

  // Diagnostics' sdk_file.state.
  static final String ABSENT = "absent";
  static final String USED = "used";
  static final String UNUSED = "unused";
  static final String REFUSED = "refused";
  static final String EXPIRED = "expired";
  static final String NOT_READ = "not_read";

  // Why a file was refused (credential-file-cases.json reasons; "" for an I/O error).
  static final String R_SYMLINK = "symlink";
  static final String R_NOT_REGULAR = "not_regular";
  static final String R_MODE = "mode";
  static final String R_OWNER = "owner";
  static final String R_TOO_LARGE = "too_large";
  static final String R_EMPTY = "empty";
  static final String R_BAD_KEY_LINE = "bad_key_line";
  static final String R_BAD_NAME_LINE = "bad_name_line";
  static final String R_REPARSE_POINT = "reparse_point";
  static final String R_OUTSIDE_LOCALAPPDATA = "outside_localappdata";

  /** The refusal of a bad key line or name line (the machine's file says the same since 0.1). */
  static final String FORMAT_PROBLEM = "the SDK credential file is not one key line followed by name=value lines; refused";

  /** The fix named when the SDK-held file is the problem. */
  static final String SETUP_FIX =
      "run setup again (npx @superbased/sdk setup --key-only, or uvx superbased-sdk setup --key-only)";

  private SdkFile() {}

  // --- path ---------------------------------------------------------------------------

  /** Whether this JVM runs on Windows. */
  static boolean windows() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
  }

  private static String env(Map<String, String> env, String name) {
    String v = env.get(name);
    return v == null ? "" : v.strip();
  }

  private static String stripTrailing(String s, String chars) {
    int end = s.length();
    while (end > 0 && chars.indexOf(s.charAt(end - 1)) >= 0) {
      end--;
    }
    return s.substring(0, end);
  }

  /** The folder the Windows rule requires the file to be inside: %LOCALAPPDATA% ("" when unset). */
  static String windowsRoot(Map<String, String> env) {
    return stripTrailing(env(env, "LOCALAPPDATA"), "\\/");
  }

  /** The SDK-held file's path for an OS ("" when none can be named). Pure. */
  static String path(Map<String, String> env, boolean onWindows) {
    String override = env(env, ENV_CREDENTIAL_FILE);
    if (!override.isEmpty()) {
      return override;
    }
    if (onWindows) {
      String base = windowsRoot(env);
      return base.isEmpty() ? "" : base + "\\" + DIR + "\\" + NAME;
    }
    String xdg = env(env, "XDG_CONFIG_HOME");
    if (xdg.startsWith("/")) {
      return stripTrailing(xdg, "/") + "/" + DIR + "/" + NAME;
    }
    String home = env(env, "HOME");
    if (!home.isEmpty()) {
      return stripTrailing(home, "/") + "/.config/" + DIR + "/" + NAME;
    }
    return "";
  }

  // --- record -----------------------------------------------------------------------------

  /** One parsed credential record. Holds the key: never log it. */
  static final class Record {
    String key = "";
    String gateway = "";
    String destination = "";
    boolean destinationLine;
    String dashboardUrl = "";
    Instant expiresAt;
    String expiresRaw = "";
    String gatewayIssue = "";
    /** The names whose line was ignored, in file order. */
    final List<String> ignored = new ArrayList<>();
    /** Why each was ignored. */
    final List<String> warnings = new ArrayList<>();
    String problem = "";
    String reason = "";

    @Override
    public String toString() {
      return "Record{gateway=" + gateway + ", destination=" + destination + "}";
    }

    private Record refuse(String why, String rule) {
      Record r = new Record();
      r.problem = why;
      r.reason = rule;
      return r;
    }

    private void ignore(String name, String why) {
      ignored.add(name);
      warnings.add(why);
    }
  }

  private static boolean printableNoSpace(String s) {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c <= ' ' || c > '~') {
        return false;
      }
    }
    return true;
  }

  private static boolean asciiText(String s) {
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if ((c < ' ' && c != '\t') || c > '~') {
        return false;
      }
    }
    return true;
  }

  /**
   * Parse a credential file's bytes (contract section 6, plus section 6a's
   * names): the first line {@code <key_id>.<secret>}, then name=value lines,
   * at most 4096 bytes, an optional final newline, CRLF read as LF. A bad
   * line shape refuses the file ({@code problem}, {@code reason}); a bad value
   * of a known name drops that name, with a warning.
   */
  static Record parse(byte[] raw) {
    Record r = new Record();
    if (raw.length == 0) {
      return r.refuse("the SDK credential file is empty; refused", R_EMPTY);
    }
    if (raw.length > LIMIT) {
      return r.refuse("the SDK credential file is over 4096 bytes; refused", R_TOO_LARGE);
    }
    String text = new String(raw, StandardCharsets.ISO_8859_1);
    if (text.endsWith("\n")) {
      text = text.substring(0, text.length() - 1);
    }
    String[] lines = text.split("\n", -1);
    for (int i = 0; i < lines.length; i++) {
      if (lines[i].endsWith("\r")) {
        lines[i] = lines[i].substring(0, lines[i].length() - 1);
      }
    }
    String key = lines[0];
    int dot = key.indexOf('.');
    if (dot <= 0 || dot == key.length() - 1 || !printableNoSpace(key)) {
      return r.refuse(FORMAT_PROBLEM, R_BAD_KEY_LINE);
    }
    Map<String, String> fields = new LinkedHashMap<>();
    for (int i = 1; i < lines.length; i++) {
      int eq = lines[i].indexOf('=');
      if (eq <= 0 || !asciiText(lines[i])) {
        return r.refuse(FORMAT_PROBLEM, R_BAD_NAME_LINE);
      }
      fields.put(lines[i].substring(0, eq), lines[i].substring(eq + 1).strip());
    }
    r.key = key;
    if (fields.containsKey(Destination.CREDENTIAL_GATEWAY_FIELD)) {
      String g = fields.get(Destination.CREDENTIAL_GATEWAY_FIELD);
      String p = Destination.gatewayProblem(g);
      if (p.isEmpty()) {
        r.gateway = Http.stripRight(g, '/');
      } else {
        r.gatewayIssue = "the SDK credential file names a gateway address that is not usable (" + p + "); it is ignored";
        r.ignore(Destination.CREDENTIAL_GATEWAY_FIELD, r.gatewayIssue);
      }
    }
    if (fields.containsKey("destination")) {
      r.destinationLine = true;
      String d = fields.get("destination");
      String v = d.toLowerCase(Locale.ROOT);
      if (v.equals(Destination.ONLINE) || v.equals(Destination.BOTH)) {
        r.destination = v;
      } else {
        r.ignore("destination", "the SDK credential file names destination '" + d + "', which is not online or both; it is ignored");
      }
    }
    if (fields.containsKey("dashboard_url")) {
      String u = fields.get("dashboard_url");
      String p = dashboardProblem(u);
      if (p.isEmpty()) {
        r.dashboardUrl = Http.stripRight(u, '/');
      } else {
        r.ignore("dashboard_url", "the SDK credential file names a dashboard address that is not usable (" + p + "); it is ignored");
      }
    }
    if (fields.containsKey("expires_at")) {
      String e = fields.get("expires_at");
      try {
        r.expiresAt = OffsetDateTime.parse(e).toInstant();
        r.expiresRaw = e;
      } catch (DateTimeParseException ex) {
        r.ignore("expires_at", "the SDK credential file's expires_at '" + e + "' is not an RFC 3339 time with a zone; it is ignored");
      }
    }
    return r;
  }

  /** "" when {@code url} is a usable dashboard base for links: https, a host, no user info, path, query or fragment. */
  static String dashboardProblem(String url) {
    URI u;
    try {
      u = URI.create(url);
    } catch (IllegalArgumentException e) {
      return "'" + url + "' is not a URL";
    }
    String host = u.getHost() == null ? "" : u.getHost();
    if (host.isEmpty() || !"https".equals(u.getScheme())) {
      return "'" + url + "' is not an https address with a host";
    }
    if (u.getRawUserInfo() != null) {
      return "'" + url + "' carries a user name or password";
    }
    String path = u.getRawPath() == null ? "" : u.getRawPath();
    if (u.getRawQuery() != null || u.getRawFragment() != null || !(path.isEmpty() || path.equals("/"))) {
      return "'" + url + "' is not a base address";
    }
    return "";
  }

  // --- reading ----------------------------------------------------------------------------

  /** What one read of the file gave. */
  static final class Held {
    String path = "";
    boolean present;
    boolean ok;
    boolean expired;
    Record record = new Record();
    String problem = "";
    String reason = "";
    final List<String> warnings = new ArrayList<>();

    /** Whether the record may serve as record 3: read and not expired. */
    boolean usable() {
      return ok && !expired;
    }

    /** The one warning a refused file gives ("" when it is not refused). */
    String refusal() {
      if (!present || problem.isEmpty()) {
        return "";
      }
      return "the SDK-held key file " + path + " is not used: " + problem;
    }
  }

  /** The file's raw bytes, or why it was refused, or that it is missing. */
  static final class Raw {
    byte[] bytes;
    String problem = "";
    String reason = "";
    boolean missing;

    static Raw missing() {
      Raw r = new Raw();
      r.missing = true;
      return r;
    }

    static Raw refused(String problem, String reason) {
      Raw r = new Raw();
      r.problem = problem;
      r.reason = reason;
      return r;
    }
  }

  /** The file reader for this OS (tests replace it). */
  interface Reader {
    Raw read(String path, String windowsRoot);
  }

  static volatile Reader reader = defaultReader();

  /** The reader for the OS this JVM runs on. */
  static Reader defaultReader() {
    return (p, root) -> windows() ? readWindows(p, root) : readUnix(p);
  }

  /** Read the SDK-held file at {@code path}; {@code root} is the Windows rule's %LOCALAPPDATA%. A missing file is not a problem. */
  static Held read(String path, String root, Instant now) {
    Held h = new Held();
    h.path = path == null ? "" : path;
    if (h.path.isEmpty()) {
      return h;
    }
    Raw raw = reader.read(path, root);
    if (raw.missing) {
      return h;
    }
    h.present = true;
    if (!raw.problem.isEmpty()) {
      h.problem = raw.problem;
      h.reason = raw.reason;
      return h;
    }
    Record r = parse(raw.bytes);
    if (!r.problem.isEmpty()) {
      h.problem = r.problem;
      h.reason = r.reason;
      return h;
    }
    h.ok = true;
    h.record = r;
    h.warnings.addAll(r.warnings);
    if (r.expiresAt != null) {
      String day = r.expiresAt.atOffset(ZoneOffset.UTC).toLocalDate().toString();
      Duration left = Duration.between(now, r.expiresAt);
      if (left.isNegative() || left.isZero()) {
        h.expired = true;
        h.warnings.add("the SDK key in " + path + " expired on " + day + ", so it is not used: " + SETUP_FIX + " to get a new one");
      } else if (left.compareTo(EXPIRY_WARNING) <= 0) {
        h.warnings.add("your SDK key expires on " + day + "; " + SETUP_FIX + " to get a new one");
      }
    }
    return h;
  }

  /** Unix: contract section 6's rules, the same as the machine's file. */
  static Raw readUnix(String path) {
    Path p = Path.of(path);
    if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) {
      return Raw.missing();
    }
    Destination.Credential c = Destination.readOwnerOnly(p);
    if (!c.error.isEmpty()) {
      return Raw.refused(c.error, c.reason);
    }
    Raw r = new Raw();
    r.bytes = c.raw;
    return r;
  }

  /** The facts the Windows rule decides on (ruling R4). */
  static final class WindowsFacts {
    boolean symlink;
    boolean reparsePoint;
    boolean regularFile;
    boolean insideRoot;
    boolean ownerIsUser;
    String ownerError = "";
  }

  /** The Windows rule, an ordered table over plain facts: {problem, reason}, {"", ""} when the file may be read. Pure. */
  static String[] windowsProblem(WindowsFacts f) {
    if (f.symlink || f.reparsePoint) {
      return new String[] {"the SDK credential file is a symlink or another reparse point; refused", R_REPARSE_POINT};
    }
    if (!f.regularFile) {
      return new String[] {"the SDK credential file is not a regular file; refused", R_NOT_REGULAR};
    }
    if (!f.insideRoot) {
      return new String[] {"the SDK credential file is not inside this user's %LOCALAPPDATA%; refused", R_OUTSIDE_LOCALAPPDATA};
    }
    if (!f.ownerError.isEmpty()) {
      return new String[] {f.ownerError, R_OWNER};
    }
    if (!f.ownerIsUser) {
      return new String[] {"the SDK credential file is owned by another user; refused", R_OWNER};
    }
    return new String[] {"", ""};
  }

  /** FILE_ATTRIBUTE_REPARSE_POINT. */
  private static final int REPARSE_POINT = 0x400;

  /**
   * Windows (ruling R4): not a reparse point (the file itself is never
   * followed), a regular file, inside {@code root} (%LOCALAPPDATA%) after every
   * link in its parent folders is resolved, whatever chose the path, owned by
   * the current user. The DACL is the writer's concern (setup sets an
   * owner-only one).
   */
  static Raw readWindows(String path, String root) {
    Path p = Path.of(path);
    BasicFileAttributes st;
    try {
      st = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    } catch (NoSuchFileException e) {
      return Raw.missing();
    } catch (IOException | RuntimeException e) {
      return Raw.refused("cannot read the SDK credential file: " + e.getMessage(), "");
    }
    WindowsFacts f = new WindowsFacts();
    f.symlink = st.isSymbolicLink();
    f.regularFile = st.isRegularFile();
    try {
      Object attrs = Files.getAttribute(p, "dos:attributes", LinkOption.NOFOLLOW_LINKS);
      f.reparsePoint = attrs instanceof Integer && (((Integer) attrs) & REPARSE_POINT) != 0;
    } catch (IOException | RuntimeException e) {
      f.reparsePoint = st.isOther();
    }
    try {
      f.insideRoot = root != null && !root.isEmpty() && insideWindowsRoot(p.toRealPath().toString(), Path.of(root).toRealPath().toString());
    } catch (IOException | RuntimeException e) {
      f.insideRoot = false;
    }
    try {
      UserPrincipal owner = Files.getOwner(p, LinkOption.NOFOLLOW_LINKS);
      f.ownerIsUser = isCurrentWindowsUser(owner);
    } catch (IOException | RuntimeException e) {
      f.ownerError = "cannot read the SDK credential file's owner: " + e.getMessage();
    }
    String[] problem = windowsProblem(f);
    if (!problem[0].isEmpty()) {
      return Raw.refused(problem[0], problem[1]);
    }
    try (SeekableByteChannel ch = Files.newByteChannel(p, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
        InputStream in = Channels.newInputStream(ch)) {
      Raw r = new Raw();
      r.bytes = in.readNBytes(LIMIT + 1);
      return r;
    } catch (IOException e) {
      return Raw.refused("cannot read the SDK credential file: " + e.getMessage(), "");
    }
  }

  /** Whether the Windows path {@code file} is strictly inside {@code dir}, without case, / as \. Pure. */
  static boolean insideWindowsRoot(String file, String dir) {
    String f = normWindows(file);
    String d = normWindows(dir);
    return !d.isEmpty() && f.startsWith(d + "\\") && f.length() > d.length() + 1;
  }

  private static String normWindows(String p) {
    String s = p.replace('/', '\\');
    if (s.startsWith("\\\\?\\")) {
      s = s.substring(4);
    }
    return stripTrailing(s, "\\").toLowerCase(Locale.ROOT);
  }

  /** Whether {@code owner} is the current Windows user (DOMAIN\name from NTSystem, else the name lookup). */
  private static boolean isCurrentWindowsUser(UserPrincipal owner) throws IOException {
    try {
      Object nt = Class.forName("com.sun.security.auth.module.NTSystem").getDeclaredConstructor().newInstance();
      String name = (String) nt.getClass().getMethod("getName").invoke(nt);
      String domain = (String) nt.getClass().getMethod("getDomain").invoke(nt);
      if (name != null && !name.isEmpty()) {
        String full = domain == null || domain.isEmpty() ? name : domain + "\\" + name;
        return owner.getName().equalsIgnoreCase(full);
      }
    } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
      // fall through to the name lookup
    }
    String me = System.getProperty("user.name", "");
    if (me.isEmpty()) {
      return false;
    }
    UserPrincipal mine = Path.of(".").getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(me);
    return owner.equals(mine);
  }

  // --- one plan's view of the file -------------------------------------------------------

  /** Reads the file at most once per plan and adds its warnings the first time. */
  static final class PlanReader {
    final String path;
    final String root;
    final Instant now;
    boolean done;
    Held held = new Held();

    PlanReader(Map<String, String> env, Instant now) {
      this.path = path(env, windows());
      this.root = windowsRoot(env);
      this.now = now;
    }

    Held get(List<String> warnings) {
      if (!done) {
        done = true;
        held = read(path, root, now);
        warnings.addAll(held.warnings);
        String w = held.refusal();
        if (!w.isEmpty()) {
          warnings.add(w);
        }
      }
      return held;
    }

    /**
     * Rung 3: the file's destination line when the file passes the read rules
     * (an expired key included: the person chose online) and the line is
     * online or both; "" otherwise. A file with no destination line says so.
     */
    String destination(List<String> warnings) {
      Held h = get(warnings);
      if (!h.ok) {
        return "";
      }
      if (!h.record.destination.isEmpty()) {
        return h.record.destination;
      }
      if (!h.record.destinationLine) {
        warnings.add("the SDK-held key file " + h.path + " has no destination line (online or both), so it does not choose the destination");
      }
      return "";
    }

    /** Diagnostics' sdk_file: path, state and the refused rule (never the key). */
    Map<String, Object> info(String keySource) {
      String state;
      String reason = "";
      if (!done) {
        state = NOT_READ;
      } else if (!held.present) {
        state = ABSENT;
      } else if (!held.ok) {
        state = REFUSED;
        reason = held.reason;
      } else if (held.expired) {
        state = EXPIRED;
      } else {
        state = SOURCE.equals(keySource) ? USED : UNUSED;
      }
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("path", path);
      out.put("state", state);
      out.put("reason", reason);
      return out;
    }

    /** The fix destination.md section 7 names for a degraded online side. */
    String degradedFix(String source, String keySource) {
      if (SOURCE.equals(source) || SOURCE.equals(keySource) || (done && held.expired)) {
        return SETUP_FIX + ", or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY";
      }
      return "run `observer sdk sign-in`, or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY";
    }
  }

  /** The credential after record 3: key, its source, gateway, dashboard. */
  static final class Applied {
    String key;
    String keySource;
    String gateway;
    String dashboard;
    final List<String> warnings = new ArrayList<>();
  }

  /**
   * Credential record 3 for a plan whose destination includes online. A key
   * and its gateway travel together: the file's key is used only with the
   * file's own gateway_url (record 1, an explicit key, may still take that
   * gateway line, never its dashboard). The machine's record, when it gave a
   * key, wins (ruling R10); the file is then named as unused.
   */
  static Applied apply(
      PlanReader r, boolean machineRecord, boolean machineKeyUsed, String key, String keySource, String gateway, String dashboard) {
    Applied a = new Applied();
    a.key = key;
    a.keySource = keySource;
    a.gateway = gateway;
    a.dashboard = dashboard;
    if (machineKeyUsed) {
      Held h = r.get(a.warnings);
      if (h.usable()) {
        a.warnings.add(
            "the SDK-held key file " + h.path + " is present but unused: this machine's own SDK key (observer sdk sign-in) is used");
      }
      return a;
    }
    if (machineRecord || (!key.isEmpty() && !gateway.isEmpty())) {
      return a;
    }
    Held h = r.get(a.warnings);
    if (!h.usable()) {
      return a;
    }
    if (key.isEmpty()) {
      if (!gateway.isEmpty() && !Http.stripRight(gateway, '/').equalsIgnoreCase(h.record.gateway)) {
        a.warnings.add(
            "the SDK-held key in "
                + h.path
                + " is for "
                + h.record.gateway
                + ", not for the organization address the app named ("
                + gateway
                + "); it is not sent there");
        return a;
      }
      a.key = h.record.key;
      a.keySource = SOURCE;
      a.dashboard = h.record.dashboardUrl;
    }
    if (gateway.isEmpty()) {
      a.gateway = h.record.gateway;
    }
    return a;
  }

  /** Discovery's online.dashboard_url when it is a usable base ("" otherwise). */
  static String discoveredDashboard(Map<String, Object> online) {
    Object v = online.get("dashboard_url");
    if (!(v instanceof String)) {
      return "";
    }
    String s = ((String) v).strip();
    return s.isEmpty() || !dashboardProblem(s).isEmpty() ? "" : Http.stripRight(s, '/');
  }
}
