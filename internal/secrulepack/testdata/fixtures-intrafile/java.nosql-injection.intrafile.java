import javax.servlet.http.HttpServletRequest;
import org.bson.Document;
import org.springframework.data.mongodb.core.query.BasicQuery;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that builds the query document.
class Queries {
    BasicQuery byName(String name) {
        // ruleid: java.nosql-injection
        return new BasicQuery("{ name: '" + name + "' }");
    }

    Object find(HttpServletRequest request) {
        return byName(request.getParameter("name"));
    }

    String requestedFilter(HttpServletRequest request) {
        return request.getHeader("X-Filter");
    }

    Object filter(HttpServletRequest request) {
        // ruleid: java.nosql-injection
        return Document.parse(requestedFilter(request));
    }

    // The sanitizer sits in the helper: the age is parsed to a number before
    // the caller builds the query document.
    int asAge(String value) {
        return Integer.parseInt(value);
    }

    Object older(HttpServletRequest request) {
        // ok: java.nosql-injection
        return new BasicQuery("{ age: { $gt: " + asAge(request.getParameter("age")) + " } }");
    }
}
