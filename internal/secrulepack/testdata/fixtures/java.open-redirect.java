import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

class LoginServlet {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
        // ruleid: java.open-redirect
        response.sendRedirect(next);
        // ok: java.open-redirect
        response.sendRedirect("/login?next=" + URLEncoder.encode(next, StandardCharsets.UTF_8));
        // ok: java.open-redirect
        response.sendRedirect("/items/" + request.getParameter("id"));
        // ruleid: java.open-redirect
        response.setHeader("Location", request.getParameter("to"));
    }
}

class AccountController {
    @GetMapping("/done")
    String done(@RequestParam String returnTo) {
        // ruleid: java.open-redirect
        return "redirect:" + returnTo;
    }

    @GetMapping("/orders/{id}")
    String order(@PathVariable String id) {
        // ok: java.open-redirect
        return "redirect:/orders/" + id;
    }
}

// The program's own values, not request input.
class Home {
    void go(HttpServletResponse response, String target) throws IOException {
        // ok: java.open-redirect
        response.sendRedirect(target);
    }
}
