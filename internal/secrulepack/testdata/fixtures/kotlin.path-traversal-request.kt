import org.apache.commons.io.FilenameUtils
import org.springframework.web.bind.annotation.*
import java.io.File
import java.nio.file.Paths
import javax.servlet.http.HttpServletRequest

@RestController
class FileController {
    private val base = Paths.get("/srv/uploads")

    @GetMapping("/files")
    fun read(@RequestParam name: String): ByteArray {
        // ruleid: kotlin.path-traversal-request
        return File("/srv/uploads/$name").readBytes()
    }

    @GetMapping("/files/{name}")
    fun resolve(@PathVariable name: String) =
        // ruleid: kotlin.path-traversal-request
        base.resolve(name).toFile().readText()

    @GetMapping("/legacy")
    fun legacy(request: HttpServletRequest) {
        // ruleid: kotlin.path-traversal-request
        Paths.get("/srv/reports", request.getParameter("report")).toFile().delete()
    }

    @GetMapping("/safe")
    fun safe(@RequestParam name: String, @RequestParam id: String) {
        // ok: kotlin.path-traversal-request
        File("/srv/uploads/" + FilenameUtils.getName(name)).readBytes()
        // ok: kotlin.path-traversal-request
        File("/srv/reports/report-${id.toLong()}.csv").readText()
        // ok: kotlin.path-traversal-request
        File("/srv/uploads/index.json").readText()
    }

    // The program's own values, not request input.
    fun cleanup(dir: String) {
        // ok: kotlin.path-traversal-request
        File(dir).deleteRecursively()
    }
}

fun Application.files() {
    routing {
        get("/download") {
            val path = call.parameters["path"]!!
            // ruleid: kotlin.path-traversal-request
            call.respondFile(File("/srv/files"), path)
        }
    }
}
