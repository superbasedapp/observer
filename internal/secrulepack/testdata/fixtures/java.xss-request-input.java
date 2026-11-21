import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class GreetingServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // ruleid: java.xss-request-input
        response.getWriter().write("<h1>Hello " + name + "</h1>");
        PrintWriter out = response.getWriter();
        // ruleid: java.xss-request-input
        out.println("<p>" + request.getHeader("Referer") + "</p>");
        // ok: java.xss-request-input
        out.println("<p>" + Encode.forHtml(name) + "</p>");
        // ok: java.xss-request-input
        out.println("<p>Welcome</p>");
    }

    @GetMapping("/echo")
    void echo(@RequestParam String text, @RequestParam int count, HttpServletResponse resp) throws IOException {
        // ruleid: java.xss-request-input
        resp.getWriter().print(text);
        // ok: java.xss-request-input
        resp.getWriter().print(count);
    }
}

// The program's own values, not request input.
class Report {
    void write(HttpServletResponse response, String html) throws IOException {
        // ok: java.xss-request-input
        response.getWriter().write(html);
    }
}
