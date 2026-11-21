import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that builds the statement.
class Accounts {
    void findByName(Connection conn, String name) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: java.sql-string-concat
        st.executeQuery("SELECT * FROM accounts WHERE name = '" + name + "'");
    }

    void lookup(Connection conn, HttpServletRequest request) throws Exception {
        findByName(conn, request.getParameter("name"));
    }

    String requestedName(HttpServletRequest request) {
        return request.getHeader("X-Owner");
    }

    void lookupReturned(Connection conn, HttpServletRequest request) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: java.sql-string-concat
        st.executeQuery("SELECT * FROM accounts WHERE owner = '" + requestedName(request) + "'");
    }

    // The sanitizer sits in the helper: the id is parsed to a number before
    // the caller builds the statement.
    int asId(String value) {
        return Integer.parseInt(value);
    }

    void lookupById(Connection conn, HttpServletRequest request) throws Exception {
        Statement st = conn.createStatement();
        // ok: java.sql-string-concat
        st.executeQuery("SELECT * FROM accounts WHERE id = " + asId(request.getParameter("id")));
    }
}
