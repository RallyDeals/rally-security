# rally-security

Shared JWT issuing/validation for GroupDeal ("Rally") microservices, so every service
doesn't reinvent Bearer-token parsing and `SecurityContext` population.

> Split out of [`rally-common`](https://github.com/RallyDeals/rally-common), which now
> holds only the shared exception hierarchy. `rally-security` depends on `rally-common`
> for `UnauthenticatedException` / `InvalidRefreshTokenException`, so adding this package
> to a service's pom.xml pulls that one in transitively.

## Structure

```
src/main/java/com/rally/security/
├── JwtProperties.java                  # binds rally.jwt.* from each service's config
├── JwtService.java                     # generate (Auth Service) / validate (everyone)
├── JwtAuthenticationFilter.java        # populates SecurityContext from the Bearer token
└── RallySecurityAutoConfiguration.java # registers JwtService/JwtAuthenticationFilter beans
                                           (unless a service already defines its own)
```

## Setup

### 1. Build and install locally

```bash
cd rally-security
mvn clean install
```

Requires `com.rally:rally-common` to already be installed/resolvable (see that repo's own
setup). Publishes `com.rally:rally-security:0.1.0` to `~/.m2`.

### 2. Publishing to GitHub Packages

CI (`.github/workflows/publish.yml`) publishes to the `RallyDeals` org's GitHub Packages
Maven registry automatically whenever a GitHub Release is published. Bump `<version>` in
`pom.xml` before cutting a release — GitHub Packages rejects re-publishing an existing
version.

### 3. Add as a dependency in each service's pom.xml

```xml
<dependency>
    <groupId>com.rally</groupId>
    <artifactId>rally-security</artifactId>
    <version>0.1.0</version>
</dependency>
```

Consuming services also need the GitHub Packages repositories registered for both
`rally-security` and `rally-common` (transitive dependency), plus the same `github` server
credentials as above (GitHub Packages requires authentication to *read* Maven packages,
even on public repos):

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/RallyDeals/rally-security</url>
    </repository>
    <repository>
        <id>github-rally-common</id>
        <url>https://maven.pkg.github.com/RallyDeals/rally-common</url>
    </repository>
</repositories>
```

### 4. Configure the shared JWT secret (same value on every service)

```yaml
rally:
  jwt:
    secret: ${JWT_SECRET}          # 256-bit minimum
    expiration-ms: 3600000
    refresh-expiration-ms: 604800000
    issuer: rally-auth-service
```

### 5. Wire the filter into each service's SecurityConfig

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```
