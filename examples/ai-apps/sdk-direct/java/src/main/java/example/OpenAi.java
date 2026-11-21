package example;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A raw OpenAI Chat Completions call with the JDK HttpClient (no OpenAI SDK),
 * so the example shows exactly which numbers go to setUsage. The key comes
 * from OPENAI_API_KEY only. Every call uses gpt-5-nano
 * (max_completion_tokens, reasoning_effort minimal, no temperature).
 */
final class OpenAi {
  static final String MODEL = "gpt-5-nano";
  private static final Gson GSON = new Gson();
  private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();

  /** What one completion returned. */
  static final class Reply {
    String id;
    String model;
    String content;
    String finishReason;
    long input;
    long output;
    long cached;
    long reasoning;
  }

  private OpenAi() {}

  static Reply chat(List<Map<String, Object>> messages, int maxTokens) throws IOException, InterruptedException {
    String key = System.getenv("OPENAI_API_KEY");
    if (key == null || key.isBlank()) {
      throw new IllegalStateException("set OPENAI_API_KEY");
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("model", MODEL);
    body.put("messages", messages);
    body.put("max_completion_tokens", maxTokens);
    body.put("reasoning_effort", "minimal");
    String base = System.getenv().getOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1");
    HttpRequest req =
        HttpRequest.newBuilder(URI.create(base.replaceAll("/+$", "") + "/chat/completions"))
            .timeout(Duration.ofSeconds(120))
            .header("Authorization", "Bearer " + key)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)))
            .build();
    HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
    if (resp.statusCode() != 200) {
      throw new IOException("OpenAI answered HTTP " + resp.statusCode() + ": " + resp.body());
    }
    JsonObject o = GSON.fromJson(resp.body(), JsonObject.class);
    Reply r = new Reply();
    r.id = o.get("id").getAsString();
    r.model = o.get("model").getAsString();
    JsonObject choice = o.getAsJsonArray("choices").get(0).getAsJsonObject();
    var content = choice.getAsJsonObject("message").get("content");
    r.content = content == null || content.isJsonNull() ? "" : content.getAsString();
    r.finishReason = choice.get("finish_reason").getAsString();
    JsonObject u = o.getAsJsonObject("usage");
    r.input = u.get("prompt_tokens").getAsLong();
    r.output = u.get("completion_tokens").getAsLong();
    if (u.has("prompt_tokens_details") && u.get("prompt_tokens_details").isJsonObject()) {
      var c = u.getAsJsonObject("prompt_tokens_details").get("cached_tokens");
      r.cached = c == null || c.isJsonNull() ? 0 : c.getAsLong();
    }
    if (u.has("completion_tokens_details") && u.get("completion_tokens_details").isJsonObject()) {
      var c = u.getAsJsonObject("completion_tokens_details").get("reasoning_tokens");
      r.reasoning = c == null || c.isJsonNull() ? 0 : c.getAsLong();
    }
    return r;
  }
}
