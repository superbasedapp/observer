import javax.crypto.Cipher;

class Seal {
    void ciphers() throws Exception {
        // ruleid: java.weak-cipher
        Cipher a = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ruleid: java.weak-cipher
        Cipher b = Cipher.getInstance("AES");
        // ruleid: java.weak-cipher
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: java.weak-cipher
        Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
        // ok: java.weak-cipher
        Cipher e = Cipher.getInstance("ChaCha20-Poly1305");
    }
}
