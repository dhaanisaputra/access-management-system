package com.example.access_management.auth.entity;

import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Entity
@Table(name = "user_sessions")
public class UserSession extends BaseEntity {

  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @Column(name = "ip_address")
  private String ipAddress;

  @Column(name = "user_agent")
  private String userAgent;

  @Column
  private String country;

  @Column
  private String city;

  @Column
  private String device;

  @Column
  private String os;

  @Column
  private String browser;

  @Column(name = "last_active", nullable = false)
  private Instant lastActive;

  @Column(name = "is_active", nullable = false)
  @Builder.Default
  private boolean isActive = true;
}
