package com.rally.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "rally.jwt")
public class JwtProperties {
    /** PEM-armored RSA public key. Matches the private key rally-auth signs access tokens with. */
    private String publicKey;
}
