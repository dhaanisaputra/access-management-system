package com.example.access_management.ai.controller;

import com.example.access_management.ai.dto.RiskAnalysisResponse;
import com.example.access_management.ai.service.AccessRiskAnalysisService;
import com.example.access_management.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Risk Analysis", description = "AI risk analysis")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/admin/risk-analysis")
@RequiredArgsConstructor
public class RiskAnalysisController {

  private final AccessRiskAnalysisService service;

  @Operation(summary = "Analyze access risks (rule-based AI)")
  @GetMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<RiskAnalysisResponse>> analyze() {
    return ResponseEntity.ok(ApiResponse.ok(service.analyze()));
  }
}
