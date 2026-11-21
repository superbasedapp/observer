import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class CleanerServlet {
    void clean(HttpServletRequest request) throws IOException {
        String dir = request.getParameter("dir");
        // ruleid: java.shell-interpolation
        new ProcessBuilder("sh", "-c", "rm -rf " + dir).start();
        // ruleid: java.shell-interpolation
        Runtime.getRuntime().exec(new String[]{"bash", "-c", String.format("tar czf %s.tgz %s", dir, dir)});
        // ruleid: java.shell-interpolation
        Runtime.getRuntime().exec("ls " + dir);
        // ok: java.shell-interpolation
        new ProcessBuilder("rm", "-rf", dir).start();
        // ok: java.shell-interpolation
        new ProcessBuilder("sh", "-c", "make clean").start();
        int n = Integer.parseInt(request.getParameter("n"));
        // ok: java.shell-interpolation
        new ProcessBuilder("sh", "-c", "tail -n " + n + " app.log").start();
    }

    @GetMapping("/ping")
    String ping(@RequestParam String host, @RequestParam int count) throws IOException {
        // ruleid: java.shell-interpolation
        new ProcessBuilder("bash", "-c", "ping -c 1 " + host).start();
        // ok: java.shell-interpolation
        new ProcessBuilder("bash", "-c", "ping -c " + count + " localhost").start();
        return "ok";
    }
}

// The program's own values, not request input.
class Cleaner {
    void clean(String dir) throws IOException {
        // ok: java.shell-interpolation
        new ProcessBuilder("sh", "-c", "rm -rf " + dir).start();
        // ok: java.shell-interpolation
        Runtime.getRuntime().exec("ls " + dir);
    }
}
