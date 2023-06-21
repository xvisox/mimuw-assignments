package pl.mimuw.carrentalback.security.jwt;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Data
public class JwtConfig {

    @Value("${visox.app.jwtSecret}")
    private String jwtSecret;

    @Value("${visox.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("${visox.app.jwtCookieName}")
    private String jwtCookie;

}
