package com.example.access_management.security.jwt;

import com.example.access_management.role.entity.Permission;
import com.example.access_management.role.entity.Role;
import com.example.access_management.user.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

  @Value("${jwt.secret}")
  private String secret;

  @Value("${jwt.access-expiration}")
  private long accessExp;

  private SecretKey key() {
    return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }

  public String generateAccessToken(User user) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(user.getId().toString())
        .id(UUID.randomUUID().toString())
        .claim("email", user.getEmail())
        .claim("roles", user.getRoles().stream().map(Role::getName).toList())
        .claim("permissions", user.getRoles().stream()
            .flatMap(r -> r.getPermissions().stream())
            .map(Permission::getName).toList())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusMillis(accessExp)))
        .signWith(key())
        .compact();
  }

  public boolean validateToken(String token) {
    try {
      Jwts.parser().verifyWith(key()).build().parseSignedClaims(token);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public String extractEmail(String token) {
    return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token)
        .getPayload().get("email", String.class);
  }

  public Long extractUserId(String token) {
    String subject = Jwts.parser().verifyWith(key()).build().parseSignedClaims(token)
        .getPayload().getSubject();
    return Long.valueOf(subject);
  }

  public String extractJti(String token) {
    return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getId();
  }

  public Date getExpiration(String token) {
    return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getExpiration();
  }

  public long getRemainingSeconds(String token) {
    Date exp = getExpiration(token);
    long diff = exp.getTime() - System.currentTimeMillis();
    return diff > 0 ? diff / 1000 : 0;
  }
}
