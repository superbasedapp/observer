// Cross-function taint in one file (--taint-intrafile): the request value is
// handed to a helper that holds the sink, or a helper returns it.
@Controller
class IntrafileController(
    val jdbcTemplate: JdbcTemplate,
    val usersCollection: MongoCollection<Document>,
    val response: HttpServletResponse,
) {
    @GetMapping("/a")
    fun a(@RequestParam value: String, request: HttpServletRequest) {
        useValue(value)
        // ruleid: kotlin.xss-request-input
        response.writer.write("<p>" + wanted(request) + "</p>")
    }

    @GetMapping("/b")
    fun b(@RequestParam value: String) {
        // ok: kotlin.xss-request-input
        response.writer.write("<p>" + cleaned(value) + "</p>")
    }

    private fun useValue(value: String) {
        // ruleid: kotlin.xss-request-input
        response.writer.write("<p>" + value + "</p>")
    }

    private fun wanted(request: HttpServletRequest): String {
        return request.getParameter("v")
    }

    // The sanitizer sits in the helper.
    private fun cleaned(value: String): String {
        return HtmlUtils.htmlEscape(value)
    }
}
