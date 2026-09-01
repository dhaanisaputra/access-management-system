package com.example.access_management.auth;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.dto.ResetPasswordRequest;
import com.example.access_management.auth.repository.PasswordResetTokenRepository;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.service.EmailService;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
class PasswordResetTest {

  @Autowired AuthService authService;
  @Autowired PasswordResetTokenRepository tokenRepository;
  @Autowired UserRepository userRepository;
  @Autowired EmailService emailService;

  @Test
  void forgot_then_reset_login_newPassword_succeeds_reuse_fails() {
    var req = new RegisterRequest("reset@test.com", "Password123", "Reset User");
    authService.register(req);

    // forgot -> token exists
    authService.forgotPassword("reset@test.com");
    String rawToken = emailService.getLastResetToken();
    assertThat(rawToken).isNotBlank();
    String hash = AuthService.sha256(rawToken);
    assertThat(tokenRepository.findByTokenHash(hash)).isPresent();

    // reset with valid token
    authService.resetPassword(new ResetPasswordRequest(rawToken, "NewPass123"));

    // login with new password succeeds
    var loginResp = authService.login(new LoginRequest("reset@test.com", "NewPass123"));
    assertThat(loginResp.accessToken()).isNotBlank();

    // old password fails
    assertThatThrownBy(() -> authService.login(new LoginRequest("reset@test.com", "Password123")))
        .isInstanceOf(BusinessException.class);

    // reuse token fails 400
    assertThatThrownBy(() -> authService.resetPassword(new ResetPasswordRequest(rawToken, "Another123")))
        .isInstanceOf(BusinessException.class);
  }

  @Test
  void expired_token_fails() {
    var req = new RegisterRequest("expire-reset@test.com", "Password123", "Expire Reset");
    authService.register(req);
    authService.forgotPassword("expire-reset@test.com");
    String raw = emailService.getLastResetToken();
    String hash = AuthService.sha256(raw);
    var token = tokenRepository.findByTokenHash(hash).orElseThrow();
    tokenRepository.delete(token);
    tokenRepository.flush();
    var user = userRepository.findByEmail("expire-reset@test.com").orElseThrow();
    var expired = com.example.access_management.auth.entity.PasswordResetToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(java.time.Instant.now().minusSeconds(3600))
        .used(false)
        .build();
    tokenRepository.save(expired);

    assertThatThrownBy(() -> authService.resetPassword(new ResetPasswordRequest(raw, "NewPass123")))
        .isInstanceOf(BusinessException.class);
  }

  @Test
  void invalid_token_fails() {
    assertThatThrownBy(() -> authService.resetPassword(new ResetPasswordRequest("invalid-raw-token", "NewPass123")))
        .isInstanceOf(BusinessException.class);
  }

  @Test
  void forgot_unknown_email_fails() {
    assertThatThrownBy(() -> authService.forgotPassword("unknown@test.com"))
        .isInstanceOf(BusinessException.class);
  }
}
