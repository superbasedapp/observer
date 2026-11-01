import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;

class Tokens2 {
    Object read(String token, SecretKey key) {
        // ruleid: java.jwt-verification-off
        Object a = JWT.require(Algorithm.none()).build().verify(token);
        // ruleid: java.jwt-verification-off
        Object b = Jwts.parser().unsecured().build().parse(token);
        // ruleid: java.jwt-verification-off
        Object c = Jwts.parser().setSigningKey(key).parseClaimsJwt(token);
        // ok: java.jwt-verification-off
        Object d = Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        // ok: java.jwt-verification-off
        Object e = JWT.require(Algorithm.HMAC256("k")).build().verify(token);
        return new Object[]{a, b, c, d, e};
    }
}
