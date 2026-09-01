package com.example.access_management.auth.scheduler;

import com.example.access_management.auth.repository.EmailVerificationTokenRepository;
import com.example.access_management.auth.repository.PasswordResetTokenRepository;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupScheduler {

  private final EmailVerificationTokenRepository emailVerificationTokenRepository;
  private final PasswordResetTokenRepository passwordResetTokenRepository;
  private final RefreshTokenRepository refreshTokenRepository;

  @Scheduled(fixedDelay = 86400000)
  @Transactional
  public void cleanup() {
    Instant now = Instant.now();
    try {
      emailVerificationTokenRepository.deleteByExpiresAtBefore(now);
      passwordResetTokenRepository.deleteByExpiresAtBefore(now);
      refreshTokenRepository.deleteByExpiresAtBefore(now);
      log.info("Token cleanup executed at {}", now);
    } catch (Exception e) {
      log.warn("Token cleanup failed: {}", e.getMessage());
    }
  }
}
