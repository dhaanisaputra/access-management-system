package com.example.access_management.auth.controller;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/v1/auth")
public interface AuthController {

  @PostMapping("/register")
  ApiResponse<UserResponse> register(@Valid @RequestBody RegisterRequest req);

  @PostMapping("/login")
  ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest req);

  @PostMapping("/refresh")
  ApiResponse<LoginResponse> refresh(@Valid @RequestBody RefreshRequest req);

  @PostMapping("/logout")
  ApiResponse<Void> logout(@Valid @RequestBody RefreshRequest req);

  @GetMapping("/me")
  ApiResponse<UserResponse> me();
}
