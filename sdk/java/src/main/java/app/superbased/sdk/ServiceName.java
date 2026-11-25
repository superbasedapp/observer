package app.superbased.sdk;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/**
 * The service name ladder (SDK quickstart plan section 3.2), first set wins:
 *
 * <ol>
 *   <li>{@code serviceName(...)} on {@link InitOptions}: source {@code argument};
 *   <li>{@code SUPERBASED_SERVICE_NAME}, {@code OTEL_SERVICE_NAME},
 *       {@code service.name} in {@code OTEL_RESOURCE_ATTRIBUTES}: {@code env};
 *   <li>{@code Implementation-Title} of the main jar's manifest (the jar run
 *       with {@code java -jar}, else the jar holding the main class),
 *       normalised: {@code manifest};
 *   <li>{@code custom-app}: {@code default}.
 * </ol>
 *
 * <p>Rung 4 of the plan (the entry script's folder) is Python's and
 * TypeScript's. Rungs 1 and 2 are used as given (trimmed; a blank one is
 * unset); only rung 3 is normalised (contract sdk-api-surface.md section 15):
 * lowercase, every character outside {@code [a-z0-9._-]} becomes {@code -},
 * runs of {@code -} become one, no leading or trailing {@code -}, {@code .}
 * or {@code _}, at most 64 characters (cut, then trimmed again).
 */
final class ServiceName {
  static final String ARGUMENT = "argument";
  static final String ENV = "env";
  static final String MANIFEST = "manifest";
  static final String DEFAULT = "default";
  static final int MAX = 64;

  private static final Pattern BAD_RUN = Pattern.compile("[^a-z0-9._-]+");
  private static final Pattern DASHES = Pattern.compile("-{2,}");

  private ServiceName() {}

  /** A name and the rung it came from. */
  static final class Resolved {
    final String name;
    final String source;

    Resolved(String name, String source) {
      this.name = name;
      this.source = source;
    }
  }

  /** The project's raw name (a variable so tests can stand in for a jar). */
  interface Project {
    String title();
  }

  static volatile Project project = ServiceName::mainJarTitle;

  /** A project-derived name as a service name ("" when nothing is left). Pure. */
  static String normalise(String raw) {
    String s = BAD_RUN.matcher(raw == null ? "" : raw.toLowerCase(Locale.ROOT)).replaceAll("-");
    s = DASHES.matcher(s).replaceAll("-");
    s = trim(s);
    if (s.length() > MAX) {
      s = s.substring(0, MAX);
    }
    return trimEnd(s);
  }

  private static String trim(String s) {
    int start = 0;
    while (start < s.length() && edge(s.charAt(start))) {
      start++;
    }
    return trimEnd(s.substring(start));
  }

  private static String trimEnd(String s) {
    int end = s.length();
    while (end > 0 && edge(s.charAt(end - 1))) {
      end--;
    }
    return s.substring(0, end);
  }

  private static boolean edge(char c) {
    return c == '-' || c == '.' || c == '_';
  }

  /** The ladder, pure: {@code projectTitle} is rung 3's raw name ("" when none). */
  static Resolved ladder(String explicit, Map<String, String> env, String projectTitle) {
    if (explicit != null && !explicit.strip().isEmpty()) {
      return new Resolved(explicit.strip(), ARGUMENT);
    }
    for (String k : new String[] {"SUPERBASED_SERVICE_NAME", "OTEL_SERVICE_NAME"}) {
      String v = env.get(k);
      if (v != null && !v.strip().isEmpty()) {
        return new Resolved(v.strip(), ENV);
      }
    }
    String attr = Util.parseKvList(env.get("OTEL_RESOURCE_ATTRIBUTES")).getOrDefault("service.name", "").strip();
    if (!attr.isEmpty()) {
      return new Resolved(attr, ENV);
    }
    String p = normalise(projectTitle);
    if (!p.isEmpty()) {
      return new Resolved(p, MANIFEST);
    }
    return new Resolved(Settings.DEFAULT_SERVICE_NAME, DEFAULT);
  }

  /** The ladder for this process. */
  static Resolved resolve(String explicit, Map<String, String> env) {
    if ((explicit != null && !explicit.strip().isEmpty()) || !Util.first(env.get("SUPERBASED_SERVICE_NAME"), env.get("OTEL_SERVICE_NAME")).isEmpty()) {
      return ladder(explicit, env, "");
    }
    String title;
    try {
      title = project.title();
    } catch (RuntimeException e) {
      title = "";
    }
    return ladder(explicit, env, title);
  }

  private static volatile String cachedTitle;

  /**
   * {@code Implementation-Title} of the main jar: the jar {@code java -jar}
   * ran (the first word of {@code sun.java.command}), else the manifest of
   * the jar holding the main class. "" when there is none. Never throws.
   */
  static String mainJarTitle() {
    String c = cachedTitle;
    if (c != null) {
      return c;
    }
    String title = "";
    try {
      String cmd = System.getProperty("sun.java.command", "").strip();
      String first = cmd.isEmpty() ? "" : cmd.split("\\s+", 2)[0];
      if (first.toLowerCase(Locale.ROOT).endsWith(".jar")) {
        title = jarTitle(first);
      } else if (!first.isEmpty()) {
        Class<?> main = Class.forName(first, false, ClassLoader.getSystemClassLoader());
        Package pkg = main.getPackage();
        if (pkg != null && pkg.getImplementationTitle() != null) {
          title = pkg.getImplementationTitle();
        }
      }
    } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
      title = "";
    }
    cachedTitle = title;
    return title;
  }

  /** {@code Implementation-Title} of the jar at {@code path} ("" when none). */
  static String jarTitle(String path) {
    try (JarFile jar = new JarFile(path, false)) {
      Manifest m = jar.getManifest();
      if (m == null) {
        return "";
      }
      String t = m.getMainAttributes().getValue(Attributes.Name.IMPLEMENTATION_TITLE);
      return t == null ? "" : t.strip();
    } catch (IOException | RuntimeException e) {
      return "";
    }
  }
}
