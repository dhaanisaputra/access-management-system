package com.example.access_management.security.jwt;

import com.example.access_management.security.service.CustomUserDetailsService;
import com.example.access_management.security.service.RedisBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final CustomUserDetailsService userDetailsService;
  private final RedisBlacklistService redisBlacklistService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String header = request.getHeader("Authorization");
    if (header != null && header.startsWith("Bearer ")) {
      String token = header.substring(7);
      if (jwtService.validateToken(token)) {
        try {
          String jti = jwtService.extractJti(token);
          if (redisBlacklistService.isBlacklisted(jti)) {
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"success\":false,\"message\":\"Token revoked\"}");
            return;
          }
          String email = jwtService.extractEmail(token);
          UserDetails userDetails = userDetailsService.loadUserByUsername(email);
          UsernamePasswordAuthenticationToken auth =
              new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
          SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception ignored) {
          // invalid token or user not found -> leave unauthenticated
        }
        MDC.put("requestId", UUID.randomUUID().toString());
      }
    }
    try {
      chain.doFilter(request, response);
    } finally {
      MDC.remove("requestId");
    }
  }
}
