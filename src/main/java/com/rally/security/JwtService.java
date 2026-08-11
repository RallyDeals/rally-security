package com.rally.security;

import com.rally.common.exceptions.domain.auth.InvalidRefreshTokenException;
import com.rally.common.exceptions.shared.UnauthenticatedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class JwtService {

    private static final String CLAIM_ROLES = "roles";

    private final JwtProperties properties;
    private final SecretKey signingKey;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /** Auth Service only. */
    public String generateAccessToken(String userId, List<String> roles) {
        return generateToken(userId, roles, properties.getExpirationMs());
    }

    /** Auth Service only. */
    public String generateRefreshToken(String userId) {
        return generateToken(userId, List.of(), properties.getRefreshExpirationMs());
    }

    private String generateToken(String userId, List<String> roles, long ttlMs) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + ttlMs);

        return Jwts.builder()
                .subject(userId)
                .issuer(properties.getIssuer())
                .claims(Map.of(CLAIM_ROLES, roles))
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    public Claims parseAndValidate(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException ex) {
            throw new UnauthenticatedException("Token expired");
        } catch (JwtException | IllegalArgumentException ex) {
            throw new UnauthenticatedException("Invalid token");
        }
    }

    public Claims parseAndValidateRefreshToken(String token) {
        try {
            return parseAndValidate(token);
        } catch (UnauthenticatedException ex) {
            throw new InvalidRefreshTokenException();
        }
    }

    public String getUserId(Claims claims) {
        return claims.getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoles(Claims claims) {
        Object roles = claims.get(CLAIM_ROLES);
        return roles == null ? List.of() : (List<String>) roles;
    }
}
