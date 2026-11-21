import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that opens it.
class Previews {
    URL open(String target) throws Exception {
        // ruleid: java.ssrf-request-url
        return new URL(target);
    }

    URL preview(HttpServletRequest request) throws Exception {
        return open(request.getParameter("url"));
    }

    String requestedUrl(HttpServletRequest request) {
        return request.getParameter("callback");
    }

    URI callback(HttpServletRequest request) {
        // ruleid: java.ssrf-request-url
        return URI.create(requestedUrl(request));
    }

    // The sanitizer sits in the helper: the value is URL-encoded before the
    // caller builds the address.
    String encoded(String value) throws Exception {
        return URLEncoder.encode(value, "UTF-8");
    }

    URL previewEncoded(HttpServletRequest request) throws Exception {
        // ok: java.ssrf-request-url
        return new URL(encoded(request.getParameter("url")));
    }
}
