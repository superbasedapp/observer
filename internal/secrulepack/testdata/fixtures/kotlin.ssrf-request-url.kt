import io.ktor.client.*
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate
import java.net.URL
import java.net.URLEncoder

@RestController
class PreviewController(val restTemplate: RestTemplate, val httpClient: HttpClient) {
    @GetMapping("/preview")
    fun preview(@RequestParam url: String): String {
        // ruleid: kotlin.ssrf-request-url
        return URL(url).readText()
    }

    @GetMapping("/proxy")
    fun proxy(@RequestHeader("X-Upstream") upstream: String): String? {
        // ruleid: kotlin.ssrf-request-url
        return restTemplate.getForObject("$upstream/status", String::class.java)
    }

    @GetMapping("/safe")
    fun safe(@RequestParam id: String, @RequestParam q: String) {
        // ok: kotlin.ssrf-request-url
        restTemplate.getForObject("https://api.example.com/users/$id", String::class.java)
        // ok: kotlin.ssrf-request-url
        URL("https://api.example.com/search?q=" + URLEncoder.encode(q, "UTF-8")).readText()
        // ok: kotlin.ssrf-request-url
        URL("https://status.example.com/health").readText()
    }

    // The program's own values, not request input.
    fun poll(endpoint: String) {
        // ok: kotlin.ssrf-request-url
        URL(endpoint).readText()
    }
}

fun Application.hooks(client: HttpClient) {
    routing {
        post("/hook") {
            val target = call.receiveParameters()["callback"]!!
            // ruleid: kotlin.ssrf-request-url
            client.get(target)
        }
    }
}
