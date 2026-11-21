import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that opens it.
class Downloads {
    FileInputStream open(String name) throws Exception {
        // ruleid: java.path-traversal-request
        return new FileInputStream(new File(name));
    }

    FileInputStream download(HttpServletRequest request) throws Exception {
        return open(request.getParameter("name"));
    }

    String requestedPath(HttpServletRequest request) {
        return request.getParameter("path");
    }

    boolean remove(HttpServletRequest request) {
        // ruleid: java.path-traversal-request
        return new File(requestedPath(request)).delete();
    }

    // The sanitizer sits in the helper: the name is reduced to its last
    // path element before the caller opens it.
    String plainName(String name) {
        return FilenameUtils.getName(name);
    }

    FileInputStream downloadPlain(HttpServletRequest request) throws Exception {
        // ok: java.path-traversal-request
        return new FileInputStream(new File(plainName(request.getParameter("name"))));
    }
}
