import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

// Cross-function taint in one file (--taint-intrafile): the value from the
// web request is handed to a helper that runs a shell.
class Backups {
    Process archive(String name) throws IOException {
        // ruleid: java.shell-interpolation
        return new ProcessBuilder("sh", "-c", "tar czf /backups/" + name + ".tgz /data").start();
    }

    void backup(HttpServletRequest request) throws IOException {
        archive(request.getParameter("name"));
    }

    String requestedHost(HttpServletRequest request) {
        return request.getHeader("X-Host");
    }

    void ping(HttpServletRequest request) throws IOException {
        // ruleid: java.shell-interpolation
        new ProcessBuilder("bash", "-c", "ping -c 1 " + requestedHost(request)).start();
    }

    // The sanitizer sits in the helper: the count is parsed to a number
    // before the caller builds the command line.
    int asCount(String value) {
        return Integer.parseInt(value);
    }

    void tail(HttpServletRequest request) throws IOException {
        // ok: java.shell-interpolation
        new ProcessBuilder("sh", "-c", "tail -n " + asCount(request.getParameter("lines")) + " app.log").start();
    }
}
