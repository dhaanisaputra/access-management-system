package com.example.access_management.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Entity
@Table(name = "login_attempts")
public class LoginAttempt {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String email;

  @Column(name = "ip_address")
  private String ipAddress;

  @Column(nullable = false)
  private boolean success;

  @Column(name = "attempted_at", nullable = false)
  private Instant attemptedAt;
}
