import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that evaluates it as a template.
class Pages {
    String renderPage(String source) {
        StringWriter w = new StringWriter();
        // ruleid: java.template-injection
        Velocity.evaluate(new VelocityContext(), w, "page", source);
        return w.toString();
    }

    String page(HttpServletRequest request) {
        return renderPage(request.getParameter("tpl"));
    }

    String requestedTemplate(HttpServletRequest request) {
        return request.getParameter("body");
    }

    String pageReturned(HttpServletRequest request) {
        StringWriter w = new StringWriter();
        // ruleid: java.template-injection
        Velocity.evaluate(new VelocityContext(), w, "page", requestedTemplate(request));
        return w.toString();
    }

    // The helper takes the request value but returns a fixed template;
    // nothing of the input becomes template source.
    String fixedTemplate(String requested) {
        return "Hello $name";
    }

    String pageFixed(HttpServletRequest request) {
        StringWriter w = new StringWriter();
        // ok: java.template-injection
        Velocity.evaluate(new VelocityContext(), w, "page", fixedTemplate(request.getParameter("tpl")));
        return w.toString();
    }
}
