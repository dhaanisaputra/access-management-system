package com.example.access_management.user.entity;

import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.role.entity.Role;
import jakarta.persistence.*;
import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
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
  private java.time.Instant lockoutUntil;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
  @Builder.Default
  private java.util.Set<Role> roles = new java.util.HashSet<>();
}
