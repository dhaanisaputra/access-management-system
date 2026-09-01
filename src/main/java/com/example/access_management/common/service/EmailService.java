package com.example.access_management.common.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailService {

  private String lastVerificationToken;
  private String lastVerificationEmail;

  public void sendVerification(String email, String rawToken) {
    this.lastVerificationEmail = email;
    this.lastVerificationToken = rawToken;
    log.info("Mock email: verify link http://localhost:8080/api/v1/auth/verify-email?token={} to {}", rawToken, email);
  }

  public void sendReset(String email, String rawToken) {
    log.info("Mock email: reset link http://localhost:8080/api/v1/auth/reset-password?token={} to {}", rawToken, email);
  }

  public String getLastVerificationToken() {
    return lastVerificationToken;
  }

  public String getLastVerificationEmail() {
    return lastVerificationEmail;
  }
}
