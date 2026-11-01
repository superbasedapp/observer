import java.security.SecureRandom;
import java.util.Random;

class Tokens {
    private final Random random = new Random();
    private final SecureRandom secure = new SecureRandom();

    String newResetToken() {
        // ruleid: java.insecure-token-randomness
        return Long.toHexString(random.nextLong());
    }

    void issue() {
        // ruleid: java.insecure-token-randomness
        int otpCode = new Random().nextInt(1000000);
        // ok: java.insecure-token-randomness
        int jitter = random.nextInt(100);
        // ok: java.insecure-token-randomness
        long sessionToken = secure.nextLong();
    }
}
