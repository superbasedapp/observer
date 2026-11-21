package app.superbased.sdk;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Small helpers shared by the SDK's classes. */
final class Util {
  /** The SDK's logger: java.util.logging, name {@code app.superbased.sdk}. */
  static final Logger LOG = Logger.getLogger("app.superbased.sdk");

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private Util() {}

  static void warn(String msg) {
    LOG.log(Level.WARNING, "superbased_sdk: " + msg);
  }

  static void info(String msg) {
    LOG.log(Level.INFO, "superbased_sdk: " + msg);
  }

  /** Trimmed, at most {@code limit} code points (no limit when {@code limit <= 0}). */
  static String clamp(String value, int limit) {
    String v = value.strip();
    if (limit <= 0 || v.codePointCount(0, v.length()) <= limit) {
      return v;
    }
    return v.substring(0, v.offsetByCodePoints(0, limit));
  }

  /** The first {@code limit} code points of {@code s}. */
  static String head(String s, int limit) {
    if (s.codePointCount(0, s.length()) <= limit) {
      return s;
    }
    return s.substring(0, s.offsetByCodePoints(0, limit));
  }

  static boolean blank(String s) {
    return s == null || s.strip().isEmpty();
  }

  /** The first argument that is set and not blank, trimmed; "" when none. */
  static String first(String... vals) {
    for (String v : vals) {
      if (v != null && !v.strip().isEmpty()) {
        return v.strip();
      }
    }
    return "";
  }

  static String hex(byte[] b) {
    char[] out = new char[b.length * 2];
    for (int i = 0; i < b.length; i++) {
      out[2 * i] = HEX[(b[i] >> 4) & 0xf];
      out[2 * i + 1] = HEX[b[i] & 0xf];
    }
    return new String(out);
  }

  static byte[] sha256(String s) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** 32 random lowercase hex characters (a UUID4's hex in Python). */
  static String randomHex32() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return hex(b);
  }

  /**
   * The OTel {@code key1=value1,key2=value2} list (percent-decoded), as used
   * by {@code OTEL_RESOURCE_ATTRIBUTES} and {@code OTEL_EXPORTER_OTLP_HEADERS}.
   * Malformed members are skipped.
   */
  static Map<String, String> parseKvList(String raw) {
    Map<String, String> out = new LinkedHashMap<>();
    if (raw == null || raw.isEmpty()) {
      return out;
    }
    for (String member : raw.split(",", -1)) {
      int eq = member.indexOf('=');
      if (eq < 0) {
        continue;
      }
      String key = unquote(member.substring(0, eq).strip());
      if (!key.isEmpty()) {
        out.put(key, unquote(member.substring(eq + 1).strip()));
      }
    }
    return out;
  }

  /** Percent-decoding as Python's {@code urllib.parse.unquote} ('+' kept). */
  static String unquote(String s) {
    if (s.indexOf('%') < 0) {
      return s;
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] in = s.getBytes(StandardCharsets.UTF_8);
    for (int i = 0; i < in.length; i++) {
      if (in[i] == '%' && i + 2 < in.length && hexVal(in[i + 1]) >= 0 && hexVal(in[i + 2]) >= 0) {
        out.write(hexVal(in[i + 1]) * 16 + hexVal(in[i + 2]));
        i += 2;
      } else {
        out.write(in[i]);
      }
    }
    return out.toString(StandardCharsets.UTF_8);
  }

  private static int hexVal(byte c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  }

  /** otelident.NormalizeTags: trimmed, clamped, de-duplicated, sorted, capped. */
  static List<String> normalizeTags(Object... lists) {
    TreeSet<String> seen = new TreeSet<>(Json::compareCodePoints);
    for (Object lst : lists) {
      if (lst == null) {
        continue;
      }
      Iterable<?> items;
      if (lst instanceof String) {
        items = List.of(((String) lst).split(",", -1));
      } else if (lst instanceof Collection) {
        items = (Collection<?>) lst;
      } else if (lst instanceof Object[]) {
        items = List.of((Object[]) lst);
      } else {
        items = List.of(lst);
      }
      for (Object t : items) {
        String s = clamp(String.valueOf(t), Keys.MAX_TAG_LEN);
        if (!s.isEmpty()) {
          seen.add(s);
        }
      }
    }
    List<String> out = new ArrayList<>(seen);
    return out.size() > Keys.MAX_TAGS ? new ArrayList<>(out.subList(0, Keys.MAX_TAGS)) : out;
  }

  /** A metadata value as text: a string as is, anything else as canonical JSON. */
  static String metaValue(Object v) {
    return v instanceof String ? (String) v : Json.canonical(v);
  }

  /**
   * otelident.NormalizeMetadata with LATER maps winning (inner scope over
   * outer): keys and values clamped, a null value deletes the key, capped at
   * MAX_METADATA_KEYS keeping the lexically smallest keys.
   */
  static Map<String, String> normalizeMetadata(List<Map<String, ?>> maps) {
    Map<String, String> out = new LinkedHashMap<>();
    for (Map<String, ?> m : maps) {
      if (m == null) {
        continue;
      }
      for (Map.Entry<String, ?> e : m.entrySet()) {
        String key = clamp(String.valueOf(e.getKey()), Keys.MAX_METADATA_KEY_LEN);
        if (key.isEmpty()) {
          continue;
        }
        if (e.getValue() == null) {
          out.remove(key);
          continue;
        }
        out.put(key, clamp(metaValue(e.getValue()), Keys.MAX_METADATA_VALUE_LEN));
      }
    }
    if (out.size() > Keys.MAX_METADATA_KEYS) {
      List<String> keys = new ArrayList<>(out.keySet());
      keys.sort(Json::compareCodePoints);
      for (String k : keys.subList(Keys.MAX_METADATA_KEYS, keys.size())) {
        out.remove(k);
      }
    }
    return out;
  }
}
