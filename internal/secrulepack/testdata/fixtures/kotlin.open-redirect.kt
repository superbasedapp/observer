import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.view.RedirectView
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Controller
class LoginController {
    @GetMapping("/login/done")
    fun done(@RequestParam next: String): String {
        // ruleid: kotlin.open-redirect
        return "redirect:$next"
    }

    @GetMapping("/back")
    fun back(request: HttpServletRequest, response: HttpServletResponse) {
        // ruleid: kotlin.open-redirect
        response.sendRedirect(request.getParameter("return_to"))
    }

    @GetMapping("/view")
    fun view(@RequestParam("to") to: String): RedirectView {
        // ruleid: kotlin.open-redirect
        return RedirectView(to)
    }

    @GetMapping("/safe")
    fun safe(@RequestParam id: String, @RequestParam item: String, response: HttpServletResponse): String {
        // ok: kotlin.open-redirect
        response.sendRedirect("/items/$id")
        // ok: kotlin.open-redirect
        response.sendRedirect("https://shop.example.com/cart?item=$item")
        // ok: kotlin.open-redirect
        return "redirect:/items/$id"
    }

    // The program's own values, not request input.
    fun home(path: String, response: HttpServletResponse) {
        // ok: kotlin.open-redirect
        response.sendRedirect(path)
    }
}

fun Application.redirects() {
    routing {
        get("/out") {
            val target = call.parameters["u"]!!
            // ruleid: kotlin.open-redirect
            call.respondRedirect(target)
        }
        get("/redirect/{n}") {
            val n = call.parameters["n"]?.toIntOrNull() ?: 0
            // ok: kotlin.open-redirect
            call.respondRedirect(if (n <= 1) "/get" else "/relative-redirect/${n - 1}")
        }
    }
}
