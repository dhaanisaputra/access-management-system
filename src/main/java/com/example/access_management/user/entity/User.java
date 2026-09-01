package com.example.access_management.user.entity;

import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.role.entity.Role;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

// ponytail: minimal stub for Task 2 compilation; Task 3 will overwrite with full fields (passwordHash, failedAttempts, lockoutUntil, etc.)
@Getter
@Setter
@Entity
@Table(name = "users")
public class User extends BaseEntity {
  @Column(unique = true, nullable = false)
  private String email;
  @Column(name = "password_hash", nullable = false)
  private String passwordHash;
  @Column(name = "full_name", nullable = false)
  private String fullName;
  @Column(nullable = false)
  private boolean enabled = true;
  @Column(name = "email_verified", nullable = false)
  private boolean emailVerified = false;
  @Column(name = "failed_attempts", nullable = false)
  private int failedAttempts = 0;
  @Column(name = "lockout_until")
  private Instant lockoutUntil;

  @ManyToMany(fetch = FetchType.LAZY)
  @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
  private Set<Role> roles = new HashSet<>();
}
