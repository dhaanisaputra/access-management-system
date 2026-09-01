package com.example.access_management.auth;

import com.example.access_management.auth.entity.RefreshToken;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class RefreshTokenRepositoryTest {
  @Autowired RefreshTokenRepository repo;
  @Autowired UserRepository userRepo;

  @Test void findByHash() {
    User u = userRepo.save(User.builder().email("r@b.com").passwordHash("x").fullName("R").build());
    RefreshToken rt = repo.save(RefreshToken.builder().user(u).tokenHash("hash123").expiresAt(Instant.now().plusSeconds(604800)).revoked(false).build());
    assertThat(repo.findByTokenHash("hash123")).isPresent();
    assertThat(repo.findByUserIdAndRevokedFalse(u.getId())).hasSize(1);
  }

  @Test void deleteByExpiresAtBefore() {
    User u = userRepo.save(User.builder().email("r2@b.com").passwordHash("x").fullName("R2").build());
    repo.save(RefreshToken.builder().user(u).tokenHash("expired1").expiresAt(Instant.now().minusSeconds(3600)).revoked(false).build());
    repo.save(RefreshToken.builder().user(u).tokenHash("valid1").expiresAt(Instant.now().plusSeconds(3600)).revoked(false).build());
    repo.deleteByExpiresAtBefore(Instant.now());
    assertThat(repo.findByTokenHash("expired1")).isEmpty();
    assertThat(repo.findByTokenHash("valid1")).isPresent();
  }
}
