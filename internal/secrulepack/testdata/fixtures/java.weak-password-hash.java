import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

class Accounts {
    void store(String password, byte[] body) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // ruleid: java.weak-password-hash
        byte[] a = md.digest(password.getBytes(StandardCharsets.UTF_8));
        // ruleid: java.weak-password-hash
        String b = DigestUtils.md5Hex(password);
        // ok: java.weak-password-hash
        byte[] c = md.digest(body);
        // ok: java.weak-password-hash
        String d = DigestUtils.sha256Hex(body);
    }
}
