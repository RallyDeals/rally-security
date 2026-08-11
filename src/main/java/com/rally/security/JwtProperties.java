package com.rally.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "rally.jwt")
public class JwtProperties {
    private String secret;
    private long expirationMs = 3_600_000;
    private long refreshExpirationMs = 604_800_000;
    private String issuer = "rally-auth-service";
}
