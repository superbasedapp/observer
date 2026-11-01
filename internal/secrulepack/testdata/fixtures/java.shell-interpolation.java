import java.io.IOException;

class Cleaner {
    void clean(String dir) throws IOException {
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
    }
}
