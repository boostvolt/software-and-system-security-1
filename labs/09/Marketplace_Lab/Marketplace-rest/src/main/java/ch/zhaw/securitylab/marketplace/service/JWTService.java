package ch.zhaw.securitylab.marketplace.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Service;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Date;

@Service
public class JWTService {
    private static final String ISSUER = "Marketplace";
    private static final long VALIDITY = 3600; // 1 hour
    private static final SecretKeySpec KEY =
            new SecretKeySpec("marketplace_12345678901234567890".getBytes(), "HmacSHA256");

    public String createJWT(String username) {
        String jwt = Jwts.builder()
                .setIssuer(ISSUER)
                .setSubject(username)
                .setExpiration(Date.from(Instant.now().plusSeconds(VALIDITY)))
                .signWith(KEY)
                .compact();
        return jwt;
    }

    public String validateJWTandGetUsername(String jwt) {
        try {
            return Jwts.parserBuilder().setSigningKey(KEY).build().
                    parseClaimsJws(jwt).getBody().getSubject();
        } catch (MalformedJwtException | SignatureException | ExpiredJwtException e) {
        }
        return null;
    }
}