package app.superbased.sdk;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

/**
 * Shared set-up (the Python suite's conftest): SDK state reset, every
 * SUPERBASED_* / OTEL_* variable unset, discovery off (a unit test never asks
 * a real machine), and the SDK's warnings captured.
 */
abstract class SdkTestBase {
  final List<String> logs = Collections.synchronizedList(new ArrayList<>());
  private final Handler handler =
      new Handler() {
        @Override
        public void publish(LogRecord r) {
          if (r.getLevel().intValue() >= Level.WARNING.intValue()) {
            logs.add(r.getMessage());
          }
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
      };

  @BeforeEach
  void cleanSdk() {
    Superbased.resetForTests();
    Env.resetForTests();
    for (String k : System.getenv().keySet()) {
      if (k.startsWith("SUPERBASED_")
          || k.startsWith("OTEL_")
          || k.startsWith("OBSERVER_CAPTURE")
          || k.equals("ANTHROPIC_OPEN_TELEMETRY")) {
        Env.set(k, null);
      }
    }
    Env.set("SUPERBASED_DISCOVER", "0");
    Util.LOG.addHandler(handler);
    Util.LOG.setUseParentHandlers(false);
  }

  @AfterEach
  void cleanAfter() {
    Util.LOG.removeHandler(handler);
    Util.LOG.setUseParentHandlers(true);
    Superbased.resetForTests();
    Env.resetForTests();
  }

  static Path contractDir() {
    String p = System.getProperty("superbased.contract.dir");
    if (p == null || p.isEmpty()) {
      p = System.getenv("SUPERBASED_CONTRACT_DIR");
    }
    if (p == null || p.isEmpty()) {
      p = "../contract";
    }
    return Path.of(p);
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> loadContract(String file) throws IOException {
    return (Map<String, Object>) Json.parse(Files.readString(contractDir().resolve(file), StandardCharsets.UTF_8));
  }
}
