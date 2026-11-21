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
        // ruleid: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + wanted(request) + "'")
    }

    @GetMapping("/b")
    fun b(@RequestParam value: String) {
        // ok: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + cleaned(value) + "'")
    }

    private fun useValue(value: String) {
        // ruleid: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + value + "'")
    }

    private fun wanted(request: HttpServletRequest): String {
        return request.getParameter("v")
    }

    // The sanitizer sits in the helper.
    private fun cleaned(value: String): String {
        return value.toLong().toString()
    }
}
