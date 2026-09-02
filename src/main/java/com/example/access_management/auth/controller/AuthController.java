package com.example.access_management.auth.controller;

import com.example.access_management.auth.dto.ForgotPasswordRequest;
import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.dto.ResendVerificationRequest;
import com.example.access_management.auth.dto.ResetPasswordRequest;
import com.example.access_management.auth.dto.VerifyEmailRequest;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.security.service.RedisBlacklistService;
import com.example.access_management.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Auth", description = "Authentication & account recovery")
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final JwtService jwtService;
  private final RedisBlacklistService redisBlacklistService;

  @Operation(summary = "Register new user")
  @PostMapping("/register")
  public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody RegisterRequest req) {
    return ResponseEntity.status(201).body(ApiResponse.created(authService.register(req)));
  }

  @Operation(summary = "Login and obtain JWT tokens")
  @PostMapping("/login")
  public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest req) {
    return ResponseEntity.ok(ApiResponse.ok(authService.login(req)));
  }

  @Operation(summary = "Refresh access token")
  @PostMapping("/refresh")
  public ResponseEntity<ApiResponse<LoginResponse>> refresh(@Valid @RequestBody RefreshRequest req) {
    return ResponseEntity.ok(ApiResponse.ok(authService.refresh(req)));
  }

  @Operation(summary = "Logout and blacklist tokens")
  @PostMapping("/logout")
  public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody RefreshRequest req,
      @RequestHeader(value = "Authorization", required = false) String authHeader) {
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String token = authHeader.substring(7);
      try {
        if (jwtService.validateToken(token)) {
          String jti = jwtService.extractJti(token);
          long ttl = jwtService.getRemainingSeconds(token);
          redisBlacklistService.blacklist(jti, ttl);
        }
      } catch (Exception ignored) {}
    }
    authService.logout(req);
    return ResponseEntity.ok(ApiResponse.ok(null, "Logged out"));
  }

  @Operation(summary = "Get current user", security = @SecurityRequirement(name = "bearerAuth"))
  @GetMapping("/me")
  public ResponseEntity<ApiResponse<UserResponse>> me() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String email = auth != null ? auth.getName() : null;
    return ResponseEntity.ok(ApiResponse.ok(authService.me(email)));
  }

  @Operation(summary = "Verify email")
  @PostMapping("/verify-email")
  public ResponseEntity<ApiResponse<UserResponse>> verifyEmail(
      @RequestParam(value = "token", required = false) String tokenParam,
      @Valid @RequestBody(required = false) VerifyEmailRequest body) {
    String token = tokenParam != null ? tokenParam : (body != null ? body.token() : null);
    if (token == null || token.isBlank()) {
      throw new com.example.access_management.common.exception.BusinessException("Token is required");
    }
    return ResponseEntity.ok(ApiResponse.ok(authService.verifyEmail(token)));
  }

  @Operation(summary = "Resend verification email")
  @PostMapping("/resend-verification")
  public ResponseEntity<ApiResponse<Void>> resendVerification(@Valid @RequestBody ResendVerificationRequest req) {
    authService.resendVerification(req.email());
    return ResponseEntity.ok(ApiResponse.ok(null, "Verification email resent"));
  }

  @Operation(summary = "Request password reset")
  @PostMapping("/forgot-password")
  public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest req) {
    authService.forgotPassword(req.email());
    return ResponseEntity.ok(ApiResponse.ok(null, "Password reset email sent"));
  }

  @Operation(summary = "Reset password")
  @PostMapping("/reset-password")
  public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest req) {
    authService.resetPassword(req);
    return ResponseEntity.ok(ApiResponse.ok(null, "Password reset successful"));
  }
}
