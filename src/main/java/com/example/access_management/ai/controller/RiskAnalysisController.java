package com.example.access_management.ai.controller;

import com.example.access_management.ai.dto.RiskAnalysisResponse;
import com.example.access_management.ai.service.AccessRiskAnalysisService;
import com.example.access_management.common.dto.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/risk-analysis")
@RequiredArgsConstructor
public class RiskAnalysisController {

  private final AccessRiskAnalysisService service;

  @GetMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<RiskAnalysisResponse>> analyze() {
    return ResponseEntity.ok(ApiResponse.ok(service.analyze()));
  }
}
