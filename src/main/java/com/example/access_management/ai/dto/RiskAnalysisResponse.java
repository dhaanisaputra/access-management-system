package com.example.access_management.ai.dto;

import java.time.Instant;
import java.util.List;

public record RiskAnalysisResponse(
    int totalUsers,
    int highRiskUsers,
    int mediumRiskUsers,
    int lowRiskUsers,
    List<UserRiskDto> topRiskyUsers,
    List<PermissionRiskDto> riskyPermissions
) {
  public record UserRiskDto(
      Long userId,
      String email,
      String fullName,
      int riskScore,
      String riskLevel,
      String lastIp,
      Instant lastLoginAt,
      List<String> reasons
  ) {}

  public record PermissionRiskDto(
      String permission,
      int userCount,
      List<String> users
  ) {}
}
