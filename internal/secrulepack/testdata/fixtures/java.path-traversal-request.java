import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PathVariable;

class Files2 {
    static final String BASE = "/srv/files";

    byte[] get(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        // ruleid: java.path-traversal-request
        FileInputStream in = new FileInputStream(new File(BASE, name));
        // ok: java.path-traversal-request
        Path safe = Paths.get(BASE).resolve(Paths.get("index.html"));
        in.close();
        return Files.readAllBytes(safe);
    }

    byte[] byId(@PathVariable String id) throws Exception {
        // ruleid: java.path-traversal-request
        return Files.readAllBytes(Paths.get(BASE, id));
    }

    byte[] byName(@PathVariable String id) throws Exception {
        // ok: java.path-traversal-request
        return Files.readAllBytes(Paths.get(BASE, Paths.get(id).getFileName().toString()));
    }
}
