package com.example.access_management.auth.repository;

import com.example.access_management.auth.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

  List<UserSession> findByUserId(Long userId);

  List<UserSession> findByUserIdAndIsActiveTrue(Long userId);

  Optional<UserSession> findTopByUserIdAndIsActiveTrueOrderByLastActiveDesc(Long userId);

  void deleteByLastActiveBefore(Instant cutoff);
}
