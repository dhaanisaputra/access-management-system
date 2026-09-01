package com.example.access_management.auth;

import com.example.access_management.auth.entity.EmailVerificationToken;
import com.example.access_management.auth.entity.PasswordResetToken;
import com.example.access_management.auth.entity.RefreshToken;
import com.example.access_management.auth.repository.EmailVerificationTokenRepository;
import com.example.access_management.auth.repository.PasswordResetTokenRepository;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import com.example.access_management.auth.scheduler.TokenCleanupScheduler;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
class TokenCleanupTest {

  @Autowired TokenCleanupScheduler scheduler;
  @Autowired EmailVerificationTokenRepository emailRepo;
  @Autowired PasswordResetTokenRepository passwordResetRepo;
  @Autowired RefreshTokenRepository refreshRepo;
  @Autowired UserRepository userRepository;

  @Test
  void cleanup_deletesExpired_butKeepsValid() {
    User user = User.create("cleanup-" + UUID.randomUUID() + "@test.com", "hash", "Cleanup User", Set.of());
    user = userRepository.save(user);

    Instant now = Instant.now();
    String expiredHash = AuthService.sha256("expired-" + UUID.randomUUID());
    String validHash = AuthService.sha256("valid-" + UUID.randomUUID());
    String expiredPrHash = AuthService.sha256("expired-pr-" + UUID.randomUUID());
    String validPrHash = AuthService.sha256("valid-pr-" + UUID.randomUUID());
    String expiredRtHash = AuthService.sha256("expired-rt-" + UUID.randomUUID());
    String validRtHash = AuthService.sha256("valid-rt-" + UUID.randomUUID());

    EmailVerificationToken expiredEvt = EmailVerificationToken.builder()
        .user(user).tokenHash(expiredHash).expiresAt(now.minusSeconds(3600)).used(false).build();
    EmailVerificationToken validEvt = EmailVerificationToken.builder()
        .user(user).tokenHash(validHash).expiresAt(now.plusSeconds(3600)).used(false).build();
    emailRepo.save(expiredEvt);
    emailRepo.save(validEvt);

    PasswordResetToken expiredPrt = PasswordResetToken.builder()
        .user(user).tokenHash(expiredPrHash).expiresAt(now.minusSeconds(3600)).used(false).build();
    PasswordResetToken validPrt = PasswordResetToken.builder()
        .user(user).tokenHash(validPrHash).expiresAt(now.plusSeconds(3600)).used(false).build();
    passwordResetRepo.save(expiredPrt);
    passwordResetRepo.save(validPrt);

    RefreshToken expiredRt = RefreshToken.builder()
        .user(user).tokenHash(expiredRtHash).expiresAt(now.minusSeconds(3600)).revoked(false).build();
    RefreshToken validRt = RefreshToken.builder()
        .user(user).tokenHash(validRtHash).expiresAt(now.plusSeconds(3600)).revoked(false).build();
    // also revoked expired should be deleted regardless
    String revokedExpiredHash = AuthService.sha256("revoked-expired-" + UUID.randomUUID());
    RefreshToken revokedExpired = RefreshToken.builder()
        .user(user).tokenHash(revokedExpiredHash).expiresAt(now.minusSeconds(3600)).revoked(true).build();
    refreshRepo.save(expiredRt);
    refreshRepo.save(validRt);
    refreshRepo.save(revokedExpired);

    // flush to ensure persisted
    emailRepo.flush();
    passwordResetRepo.flush();
    refreshRepo.flush();

    assertThat(emailRepo.findByTokenHash(expiredHash)).isPresent();
    assertThat(passwordResetRepo.findByTokenHash(expiredPrHash)).isPresent();
    assertThat(refreshRepo.findByTokenHash(expiredRtHash)).isPresent();

    scheduler.cleanup();

    // expired deleted
    assertThat(emailRepo.findByTokenHash(expiredHash)).isEmpty();
    assertThat(passwordResetRepo.findByTokenHash(expiredPrHash)).isEmpty();
    assertThat(refreshRepo.findByTokenHash(expiredRtHash)).isEmpty();
    assertThat(refreshRepo.findByTokenHash(revokedExpiredHash)).isEmpty();

    // valid still present
    assertThat(emailRepo.findByTokenHash(validHash)).isPresent();
    assertThat(passwordResetRepo.findByTokenHash(validPrHash)).isPresent();
    assertThat(refreshRepo.findByTokenHash(validRtHash)).isPresent();
  }
}
