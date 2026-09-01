package com.example.access_management.auth.entity;

import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken extends BaseEntity {

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @Column(name = "token_hash", unique = true, nullable = false)
  private String tokenHash;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(nullable = false)
  @Builder.Default
  private boolean used = false;

  public void markUsed() {
    this.used = true;
  }

  public boolean isExpired() {
    return expiresAt.isBefore(Instant.now());
  }
}
