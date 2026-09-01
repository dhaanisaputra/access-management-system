package com.example.access_management.security.service;

import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.entity.RefreshToken;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import com.example.access_management.auth.service.OAuthAccountService;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

  private final OAuthAccountService oAuthAccountService;
  private final JwtService jwtService;
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;
  private final ObjectMapper objectMapper;

  @Value("${jwt.access-expiration}")
  private long accessExp;

  @Value("${jwt.refresh-expiration}")
  private long refreshExp;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException {
    OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
    String provider = token.getAuthorizedClientRegistrationId();
    OAuth2User principal = token.getPrincipal();

    String providerUserId = extractProviderUserId(principal);
    String email = principal.getAttribute("email");
    String name = principal.getAttribute("name");
    if (name == null) name = principal.getAttribute("given_name");

    LoginResponse loginResponse = handle(provider, providerUserId, email, name);

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    ApiResponse<LoginResponse> body = ApiResponse.ok(loginResponse);
    objectMapper.writeValue(response.getWriter(), body);
  }

  // testable entry point without HttpServlet* mocks
  public LoginResponse handle(String provider, String providerUserId, String email, String fullName) {
    User user = oAuthAccountService.processOAuthUser(provider, providerUserId, email, fullName);
    // reload with roles/permissions so JWT contains them
    User enriched = userRepository.findByEmailWithRolesAndPermissions(user.getEmail())
        .orElse(user);
    String accessToken = jwtService.generateAccessToken(enriched);

    String rawRefresh = UUID.randomUUID().toString();
    String hash = sha256(rawRefresh);
    RefreshToken rt = RefreshToken.builder()
        .user(enriched)
        .tokenHash(hash)
        .expiresAt(Instant.now().plusMillis(refreshExp))
        .revoked(false)
        .build();
    refreshTokenRepository.save(rt);

    return new LoginResponse(accessToken, rawRefresh, accessExp, "Bearer");
  }

  private String extractProviderUserId(OAuth2User principal) {
    Object sub = principal.getAttribute("sub");
    if (sub != null) return sub.toString();
    Object id = principal.getAttribute("id");
    if (id != null) return id.toString();
    return principal.getName();
  }

  private static String sha256(String token) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
      StringBuilder hex = new StringBuilder(hash.length * 2);
      for (byte b : hash) hex.append(String.format("%02x", b));
      return hex.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
