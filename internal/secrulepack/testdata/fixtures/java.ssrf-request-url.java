import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

class Preview {
    RestTemplate rest = new RestTemplate();

    String fetch(HttpServletRequest request) throws Exception {
        // ruleid: java.ssrf-request-url
        URL u = new URL(request.getParameter("url"));
        // ok: java.ssrf-request-url
        URL v = new URL("https://api.example.com/search?q=" + URLEncoder.encode(request.getParameter("q"), StandardCharsets.UTF_8));
        return u.toString() + v;
    }

    String hook(@RequestParam String callback) {
        // ruleid: java.ssrf-request-url
        String a = rest.getForObject(callback, String.class);
        // ok: java.ssrf-request-url
        String b = rest.getForObject("https://api.example.com/users/" + callback, String.class);
        // ok: java.ssrf-request-url
        URI c = URI.create("https://api.example.com/status");
        return a + b + c;
    }
}
