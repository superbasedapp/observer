import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that writes it to the response.
class Pages {
    void heading(HttpServletResponse response, String text) throws IOException {
        // ruleid: java.xss-request-input
        response.getWriter().write("<h1>" + text + "</h1>");
    }

    void show(HttpServletRequest request, HttpServletResponse response) throws IOException {
        heading(response, request.getParameter("title"));
    }

    String requestedNote(HttpServletRequest request) {
        return request.getParameter("note");
    }

    void note(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ruleid: java.xss-request-input
        response.getWriter().write("<p>" + requestedNote(request) + "</p>");
    }

    // The sanitizer sits in the helper: the value is encoded before the
    // caller writes it.
    String encoded(String value) {
        return Encode.forHtml(value);
    }

    void comment(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java.xss-request-input
        response.getWriter().write("<p>" + encoded(request.getParameter("comment")) + "</p>");
    }
}
