import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
import java.sql.Connection
import javax.persistence.EntityManager
import javax.servlet.http.HttpServletRequest

@RestController
class UserController(val jdbcTemplate: JdbcTemplate, val em: EntityManager, val conn: Connection) {
    @GetMapping("/users")
    fun search(@RequestParam name: String): List<Map<String, Any>> {
        // ruleid: kotlin.sql-string-concat
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '$name'")
    }

    @GetMapping("/users/{sort}")
    fun sorted(@PathVariable("sort") sort: String) =
        // ruleid: kotlin.sql-string-concat
        em.createNativeQuery("SELECT * FROM users ORDER BY " + sort).resultList

    @GetMapping("/legacy")
    fun legacy(request: HttpServletRequest) {
        val st = conn.createStatement()
        // ruleid: kotlin.sql-string-concat
        st.executeQuery("SELECT * FROM t WHERE c = '${request.getParameter("c")}'")
    }

    @GetMapping("/safe")
    fun safe(@RequestParam name: String, @RequestParam id: String, @RequestParam page: Int) {
        // ok: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name)
        // ok: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users WHERE id = ${id.toLong()}")
        // ok: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT * FROM users LIMIT 20 OFFSET $page")
    }

    // The program's own values, not request input.
    fun report(column: String) {
        // ok: kotlin.sql-string-concat
        jdbcTemplate.queryForList("SELECT $column FROM stats")
    }
}

fun Application.users() {
    routing {
        get("/find") {
            val email = call.request.queryParameters["email"]
            // ruleid: kotlin.sql-string-concat
            transaction { exec("SELECT * FROM users WHERE email = '$email'") }
        }
    }
}
