import org.springframework.web.bind.annotation.*
import org.springframework.web.util.HtmlUtils
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller
class SearchController {
    @GetMapping("/search")
    fun search(@RequestParam q: String, response: HttpServletResponse) {
        // ruleid: kotlin.xss-request-input
        response.writer.write("<p>Results for $q</p>")
    }

    @GetMapping("/legacy")
    fun legacy(request: HttpServletRequest, response: HttpServletResponse) {
        // ruleid: kotlin.xss-request-input
        response.getWriter().println("<h1>" + request.getParameter("title") + "</h1>")
    }

    @GetMapping("/safe")
    fun safe(@RequestParam q: String, @RequestParam page: String, response: HttpServletResponse) {
        // ok: kotlin.xss-request-input
        response.writer.write("<p>Results for ${HtmlUtils.htmlEscape(q)}</p>")
        // ok: kotlin.xss-request-input
        response.writer.write("Page ${page.toInt()}")
    }

    // The program's own values, not request input.
    fun badge(label: String, response: HttpServletResponse) {
        // ok: kotlin.xss-request-input
        response.writer.write("<span class=\"badge\">$label</span>")
    }
}

fun Application.pages() {
    routing {
        get("/hello") {
            val name = call.parameters["name"]
            // ruleid: kotlin.xss-request-input
            call.respondText("<h1>Hello $name</h1>", ContentType.Text.Html)
            // ok: kotlin.xss-request-input
            call.respondText("Hello $name")
        }
        get("/note") {
            val note = call.request.queryParameters["note"]
            call.respondHtml {
                body {
                    unsafe {
                        // ruleid: kotlin.xss-request-input
                        +"<div>$note</div>"
                    }
                }
            }
        }
    }
}
