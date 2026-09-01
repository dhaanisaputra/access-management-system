package com.example.access_management.auth;

import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.repository.EmailVerificationTokenRepository;
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
class EmailVerificationTest {

  @Autowired AuthService authService;
  @Autowired EmailVerificationTokenRepository tokenRepository;
  @Autowired UserRepository userRepository;
  @Autowired EmailService emailService;

  @Test
  void register_then_verify_then_verifyAgainFails_resendCreatesNewToken() {
    // register -> token exists
    var req = new RegisterRequest("verify@test.com", "Password123", "Verify User");
    var userResp = authService.register(req);
    assertThat(userResp.email()).isEqualTo("verify@test.com");
    assertThat(userResp.emailVerified()).isFalse();

    String rawToken = emailService.getLastVerificationToken();
    assertThat(rawToken).isNotBlank();
    String hash = AuthService.sha256(rawToken);
    assertThat(tokenRepository.findByTokenHash(hash)).isPresent();

    // verify -> emailVerified true
    var verified = authService.verifyEmail(rawToken);
    assertThat(verified.emailVerified()).isTrue();
    assertThat(userRepository.findByEmail("verify@test.com").orElseThrow().isEmailVerified()).isTrue();

    // verify again fails 400 (BusinessException)
    assertThatThrownBy(() -> authService.verifyEmail(rawToken))
        .isInstanceOf(BusinessException.class);

    // resend for already verified should fail
    assertThatThrownBy(() -> authService.resendVerification("verify@test.com"))
        .isInstanceOf(BusinessException.class);

    // resend creates new token for unverified user
    var req2 = new RegisterRequest("verify2@test.com", "Password123", "Verify2");
    authService.register(req2);
    String oldRaw = emailService.getLastVerificationToken();
    String oldHash = AuthService.sha256(oldRaw);
    assertThat(tokenRepository.findByTokenHash(oldHash)).isPresent();

    authService.resendVerification("verify2@test.com");
    String newRaw = emailService.getLastVerificationToken();
    assertThat(newRaw).isNotEqualTo(oldRaw);
    String newHash = AuthService.sha256(newRaw);
    assertThat(tokenRepository.findByTokenHash(newHash)).isPresent();
    // old token should be deleted
    assertThat(tokenRepository.findByTokenHash(oldHash)).isEmpty();
  }

  @Test
  void verify_invalidToken_fails() {
    assertThatThrownBy(() -> authService.verifyEmail("invalid-raw-token"))
        .isInstanceOf(BusinessException.class);
  }

  @Test
  void verify_expiredToken_fails() {
    var req = new RegisterRequest("expire@test.com", "Password123", "Expire User");
    authService.register(req);
    String raw = emailService.getLastVerificationToken();
    String hash = AuthService.sha256(raw);
    var token = tokenRepository.findByTokenHash(hash).orElseThrow();
    // force expire by recreating with past expiresAt via reflection? simplest: delete and create expired
    tokenRepository.delete(token);
    tokenRepository.flush();
    var user = userRepository.findByEmail("expire@test.com").orElseThrow();
    var expired = com.example.access_management.auth.entity.EmailVerificationToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(java.time.Instant.now().minusSeconds(3600))
        .used(false)
        .build();
    tokenRepository.save(expired);

    assertThatThrownBy(() -> authService.verifyEmail(raw))
        .isInstanceOf(BusinessException.class);
  }
}
