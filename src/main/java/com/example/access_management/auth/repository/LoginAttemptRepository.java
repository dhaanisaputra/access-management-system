package com.example.access_management.auth.repository;

import com.example.access_management.auth.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

  long countByEmailAndSuccessFalseAndAttemptedAtAfter(String email, Instant after);

  long countByEmail(String email);

  List<LoginAttempt> findByEmail(String email);
}
