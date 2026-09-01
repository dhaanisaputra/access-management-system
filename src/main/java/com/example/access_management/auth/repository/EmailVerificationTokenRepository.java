package com.example.access_management.auth.repository;

import com.example.access_management.auth.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

  Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

  List<EmailVerificationToken> findByUserIdAndUsedFalse(Long userId);

  void deleteByExpiresAtBefore(Instant instant);
}
