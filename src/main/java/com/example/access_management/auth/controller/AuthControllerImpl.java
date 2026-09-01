package com.example.access_management.auth.controller;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthControllerImpl implements AuthController {

  private final AuthService authService;

  @Override
  public ApiResponse<UserResponse> register(RegisterRequest req) {
    return ApiResponse.created(authService.register(req));
  }

  @Override
  public ApiResponse<LoginResponse> login(LoginRequest req) {
    return ApiResponse.ok(authService.login(req));
  }

  @Override
  public ApiResponse<LoginResponse> refresh(RefreshRequest req) {
    return ApiResponse.ok(authService.refresh(req));
  }

  @Override
  public ApiResponse<Void> logout(RefreshRequest req) {
    authService.logout(req);
    return ApiResponse.ok(null, "Logged out");
  }

  @Override
  public ApiResponse<UserResponse> me() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String email = auth != null ? auth.getName() : null;
    return ApiResponse.ok(authService.me(email));
  }
}
