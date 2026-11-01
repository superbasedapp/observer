import freemarker.template.Configuration;
import freemarker.template.Template;
import java.io.StringReader;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.RequestParam;

class Pages {
    String render(HttpServletRequest request, Configuration cfg) throws Exception {
        StringWriter w = new StringWriter();
        // ruleid: java.template-injection
        Velocity.evaluate(new VelocityContext(), w, "page", request.getParameter("tpl"));
        // ruleid: java.template-injection
        Template t = new Template("page", new StringReader(request.getParameter("body")), cfg);
        // ok: java.template-injection
        Velocity.evaluate(new VelocityContext(), w, "page", "Hello $name");
        return w.toString() + t.getName();
    }

    Object expr(@RequestParam String q) {
        SpelExpressionParser parser = new SpelExpressionParser();
        // ruleid: java.template-injection
        Object a = parser.parseExpression(q).getValue();
        // ok: java.template-injection
        Object b = parser.parseExpression("1 + 1").getValue();
        return a.toString() + b;
    }
}
