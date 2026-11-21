import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that redirects to it.
class Redirects {
    void sendTo(HttpServletResponse response, String target) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect(target);
    }

    void done(HttpServletRequest request, HttpServletResponse response) throws IOException {
        sendTo(response, request.getParameter("next"));
    }

    String returnTarget(HttpServletRequest request) {
        return request.getParameter("returnTo");
    }

    void finish(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.open-redirect
        response.sendRedirect(returnTarget(request));
    }

    // The sanitizer sits in the helper: the value is encoded before the
    // caller redirects to it.
    String encoded(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    void bounce(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java.open-redirect
        response.sendRedirect(encoded(request.getParameter("next")));
    }
}
