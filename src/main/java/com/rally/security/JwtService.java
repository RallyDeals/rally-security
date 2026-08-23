package com.rally.security;

import com.rally.common.exceptions.domain.auth.InvalidRefreshTokenException;
import com.rally.common.exceptions.shared.UnauthenticatedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/**
 * Verification only — tokens are signed exclusively by the Auth Service (RS256, its own
 * RSA private key). This service holds only the matching public key, so it can validate
 * signatures but never mint tokens.
 */
public class JwtService {

    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_USERNAME = "name";

    private final PublicKey verificationKey;

    public JwtService(JwtProperties properties) {
        this.verificationKey = parsePublicKey(properties.getPublicKey());
    }

    private static PublicKey parsePublicKey(String pem) {
        try {
            String der = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(der)));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid RSA public key", e);
        }
    }

    public Claims parseAndValidate(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(verificationKey)
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

    public String getUsername(Claims claims) {
        return claims.get(CLAIM_USERNAME, String.class);
    }

    public List<String> getRoles(Claims claims) {
        String role = claims.get(CLAIM_ROLE, String.class);
        return (role == null || role.isEmpty()) ? List.of() : List.of(role);
    }
}
