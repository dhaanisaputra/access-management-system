package com.example.access_management.user.entity;

import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.role.entity.Role;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA only
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Entity @Table(name = "users")
public class User extends BaseEntity {

  @Column(unique = true, nullable = false)
  private String email;

  @Column(name = "password_hash", nullable = false)
  private String passwordHash;

  @Column(name = "full_name", nullable = false)
  private String fullName;

  @Column(nullable = false)
  @Builder.Default
  private boolean enabled = true;

  @Column(name = "email_verified", nullable = false)
  @Builder.Default
  private boolean emailVerified = false;

  @Column(name = "failed_attempts", nullable = false)
  @Builder.Default
  private int failedAttempts = 0;

  @Column(name = "lockout_until")
  private Instant lockoutUntil;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
  @Builder.Default
  private Set<Role> roles = new HashSet<>();

  // === Factory ===
  public static User create(String email, String passwordHash, String fullName, Set<Role> roles) {
    return User.builder()
        .email(email)
        .passwordHash(passwordHash)
        .fullName(fullName)
        .roles(roles != null ? new HashSet<>(roles) : new HashSet<>())
        .build();
  }

  // === Behavior (rich domain) ===
  public boolean isLocked() {
    return lockoutUntil != null && lockoutUntil.isAfter(Instant.now());
  }

  public void recordFailedAttempt(int threshold, long lockoutMinutes) {
    this.failedAttempts++;
    if (this.failedAttempts >= threshold) {
      this.lockoutUntil = Instant.now().plusSeconds(lockoutMinutes * 60);
    }
  }

  public void resetLockout() {
    this.failedAttempts = 0;
    this.lockoutUntil = null;
  }

  public void assignRole(Role role) {
    this.roles.add(role);
  }

  public void verifyEmail() {
    this.emailVerified = true;
  }

  // For password change (future Fase 2)
  public void changePasswordHash(String newHash) {
    this.passwordHash = newHash;
  }

  public void changeFullName(String newName) {
    this.fullName = newName;
  }
}
