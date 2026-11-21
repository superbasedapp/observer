package example;

import app.superbased.sdk.Evaluator;
import app.superbased.sdk.ExperimentGateFailedException;
import app.superbased.sdk.ExperimentOptions;
import app.superbased.sdk.ExperimentResult;
import app.superbased.sdk.InitOptions;
import app.superbased.sdk.SbSpan;
import app.superbased.sdk.Superbased;
import app.superbased.sdk.Usage;
import java.util.List;
import java.util.Map;

/**
 * A small dataset experiment with a CI gate ({@code failUnder}).
 *
 * <p>Runs a tiny golden set through the same model call the chatbot makes and
 * scores each answer with an exact-match evaluator. {@code failUnder(0.5)}
 * makes the program exit 1 ({@link ExperimentGateFailedException}) when fewer
 * than half of the items pass. On this machine the dataset is created on
 * first use; on the organization it must exist first, and the key needs the
 * {@code sdk:eval} scope (a CI credential).
 */
public final class Experiment {
  private Experiment() {}

  static Object task(Object input) {
    String q = String.valueOf(input);
    try (SbSpan s = Superbased.llmSpan("answer").model(OpenAi.MODEL).provider("openai").prompt(q).start()) {
      OpenAi.Reply r = OpenAi.chat(List.of(Map.of("role", "user", "content", q)), 300);
      String out = r.content.strip().replaceAll("\\.$", "");
      s.setUsage(
          Usage.builder()
              .inputTokens(r.input)
              .outputTokens(r.output)
              .responseId(r.id)
              .responseModel(r.model)
              .response(out)
              .build());
      return out;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static void main(String[] args) {
    Superbased.init(InitOptions.builder().serviceName(Chatbot.env("SUPERBASED_SERVICE_NAME", "sdk-direct-evals")).build());
    String dataset = Chatbot.env("DATASET_NAME", "capitals-golden");
    List<Object> items =
        List.of(
            Map.of("id", "fr", "input", "Capital of France? One word.", "expected", "Paris"),
            Map.of("id", "jp", "input", "Capital of Japan? One word.", "expected", "Tokyo"));
    Evaluator exact =
        Evaluator.of("exact_match", "1", in -> String.valueOf(in.output()).equalsIgnoreCase(String.valueOf(in.expected())));
    int code = 0;
    try {
      ExperimentResult result =
          Superbased.runExperiment(
              items,
              ExperimentOptions.builder()
                  .inputTask(Experiment::task)
                  .evaluator(exact)
                  .datasetName(dataset)
                  .name("capitals-" + System.currentTimeMillis() / 1000)
                  .failUnder(0.5)
                  .build());
      System.out.println("pass_rate: " + result.passRate() + " scored: " + result.scored() + " runs: " + result.runs());
      System.out.println("errors: " + result.errors());
      System.out.println("summary: " + result.summary());
    } catch (ExperimentGateFailedException e) {
      System.out.println(e.getMessage());
      code = e.exitCode();
    } finally {
      Superbased.shutdown();
    }
    System.exit(code);
  }
}
