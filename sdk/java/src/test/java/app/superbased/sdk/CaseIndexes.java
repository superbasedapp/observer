package app.superbased.sdk;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.ParameterDeclarations;

/**
 * Supplies the case indexes of the sdk-behaviour-cases.json section named
 * like the test method, so each case runs as its own test with the per-test
 * set-up (a fresh SDK) around it.
 */
final class CaseIndexes implements ArgumentsProvider {
  @Override
  @SuppressWarnings("unchecked")
  public Stream<? extends Arguments> provideArguments(ParameterDeclarations parameters, ExtensionContext context)
      throws Exception {
    String section = context.getRequiredTestMethod().getName();
    Map<String, Object> all = SdkTestBase.loadContract("sdk-behaviour-cases.json");
    Map<String, Object> sec = (Map<String, Object>) all.get(section);
    if (sec == null) {
      throw new IllegalStateException("sdk-behaviour-cases.json has no section " + section);
    }
    int n = ((List<Object>) sec.get("cases")).size();
    return IntStream.range(0, n).mapToObj(Arguments::of);
  }
}
