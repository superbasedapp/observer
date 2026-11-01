import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

class TrustAll implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    // ruleid: java.tls-verify-off
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}

class Strict implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    // ok: java.tls-verify-off
    public void checkServerTrusted(X509Certificate[] chain, String authType) { delegate(chain, authType); }

    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

    void delegate(X509Certificate[] chain, String authType) {}
}

class Conn {
    void open(HttpsURLConnection c, HostnameVerifier strict) {
        // ruleid: java.tls-verify-off
        c.setHostnameVerifier((host, session) -> true);
        // ruleid: java.tls-verify-off
        Object v = NoopHostnameVerifier.INSTANCE;
        // ok: java.tls-verify-off
        c.setHostnameVerifier(strict);
    }
}
