package com.example.access_management.auth.dto;

import java.util.List;

public record LoginResponse(String accessToken, String refreshToken, long expiresIn, String tokenType,
                            int riskScore, String riskLevel, boolean suspicious, List<String> riskReasons) {
  public LoginResponse(String accessToken, String refreshToken, long expiresIn, String tokenType) {
    this(accessToken, refreshToken, expiresIn, tokenType, 0, "LOW", false, List.of());
  }
}
