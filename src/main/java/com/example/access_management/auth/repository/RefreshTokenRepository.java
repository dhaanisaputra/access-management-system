package com.example.access_management.auth.repository;

import com.example.access_management.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  Optional<RefreshToken> findByTokenHash(String tokenHash);

  @Modifying
  @Transactional
  void deleteByExpiresAtBefore(Instant instant);

  List<RefreshToken> findByUserIdAndRevokedFalse(Long userId);
}
