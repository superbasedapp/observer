import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletRequest

@RestController
class ToolController {
    @PostMapping("/convert")
    fun convert(@RequestParam file: String) {
        // ruleid: kotlin.shell-interpolation
        Runtime.getRuntime().exec("convert $file out.png")
        // ruleid: kotlin.shell-interpolation
        ProcessBuilder("sh", "-c", "tar czf /tmp/out.tgz $file").start()
    }

    @GetMapping("/ping")
    fun ping(request: HttpServletRequest) {
        val host = request.getParameter("host")
        // ruleid: kotlin.shell-interpolation
        Runtime.getRuntime().exec(arrayOf("/bin/bash", "-c", "ping -c 1 $host"))
    }

    @GetMapping("/safe")
    fun safe(@RequestParam file: String, @RequestParam pid: String) {
        // ok: kotlin.shell-interpolation
        ProcessBuilder("convert", file, "out.png").start()
        // ok: kotlin.shell-interpolation
        Runtime.getRuntime().exec(arrayOf("convert", file, "out.png"))
        // ok: kotlin.shell-interpolation
        Runtime.getRuntime().exec("kill -HUP ${pid.toInt()}")
    }

    // The program's own values, not request input.
    fun rotate(path: String) {
        // ok: kotlin.shell-interpolation
        Runtime.getRuntime().exec("logrotate $path")
    }
}

fun Application.tools() {
    routing {
        post("/run") {
            val script = call.receiveText()
            // ruleid: kotlin.shell-interpolation
            ProcessBuilder(listOf("sh", "-c", script)).start()
        }
    }
}
