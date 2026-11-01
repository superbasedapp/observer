import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

class Cors {
    void register(CorsRegistry registry) {
        // ruleid: java.cors-credentials-any-origin
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
        // ok: java.cors-credentials-any-origin
        registry.addMapping("/**").allowedOrigins("https://app.example.com").allowCredentials(true);
    }

    CorsConfiguration config() {
        CorsConfiguration c = new CorsConfiguration();
        // ruleid: java.cors-credentials-any-origin
        c.setAllowedOriginPatterns(List.of("*"));
        c.setAllowCredentials(true);
        return c;
    }

    CorsConfiguration open() {
        CorsConfiguration c = new CorsConfiguration();
        // ok: java.cors-credentials-any-origin
        c.addAllowedOriginPattern("*");
        return c;
    }

    void filter(HttpServletRequest request, HttpServletResponse response) {
        // ruleid: java.cors-credentials-any-origin
        response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }
}
