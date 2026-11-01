import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class Accounts {
    private static final String TABLE = "accounts";
    private JdbcTemplate jdbc;

    public void byName(Connection conn, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement st = conn.createStatement();
        // ruleid: java.sql-string-concat
        st.executeQuery("SELECT * FROM accounts WHERE name = '" + name + "'");
        String q = String.format("DELETE FROM accounts WHERE owner = '%s'", request.getHeader("X-Owner"));
        // ruleid: java.sql-string-concat
        st.executeUpdate(q);
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name = ?");
        // ok: java.sql-string-concat
        ps.setString(1, name);
        int id = Integer.parseInt(request.getParameter("id"));
        // ok: java.sql-string-concat
        st.executeQuery("SELECT * FROM accounts WHERE id = " + id);
    }

    @GetMapping("/find")
    public Object find(@RequestParam("region") String region) {
        // ruleid: java.sql-string-concat
        return jdbc.queryForList("SELECT * FROM accounts WHERE region = '" + region + "'");
    }

    public void internal(Statement st, String column) throws Exception {
        // ok: java.sql-string-concat
        st.executeQuery("SELECT " + column + " FROM " + TABLE);
        StringBuilder marks = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            marks.append(i == 0 ? "?" : ",?");
        }
        // ok: java.sql-string-concat
        st.executeQuery("SELECT * FROM " + TABLE + " WHERE id IN (" + marks + ")");
    }

    // Pack 1.3.1 near-misses, the shapes the SEC-G5 corpus reviewers named
    // (46 wrong matches): a service's update or query, a URI builder.
    @PutMapping("/{id}")
    public Object update(@PathVariable("id") final String id, @RequestBody Resource resources) {
        // ok: java.sql-string-concat
        resourceService.update(resources);
        // ok: java.sql-string-concat
        return userService.update(id, resources);
    }

    @GetMapping("/list")
    public Object list(@RequestParam Integer page, @RequestParam String sort) {
        // ok: java.sql-string-concat
        return brandService.query(page, sort);
    }

    public void forward(HttpServletRequest request) {
        // ok: java.sql-string-concat
        UriComponentsBuilder.fromUri(null).query(request.getQueryString());
    }

    @GetMapping("/byid")
    public Object byId(@RequestParam("id") Long id) throws Exception {
        // ok: java.sql-string-concat
        return jdbc.queryForList("SELECT * FROM accounts WHERE id = " + id);
    }

    // Pack 1.3.1 positives: SQL text built first, a final parameter, a
    // receiver known by its name.
    @GetMapping("/by")
    public Object by(@RequestParam("col") final String col) throws Exception {
        String sql = "SELECT * FROM accounts ORDER BY " + col;
        // ruleid: java.sql-string-concat
        return jdbcTemplate.queryForList(sql);
    }

    public void raw(Statement stmt, @RequestBody String body) throws Exception {
        // ruleid: java.sql-string-concat
        stmt.execute("INSERT INTO notes VALUES ('" + body + "')");
    }
}
