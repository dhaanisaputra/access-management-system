package com.example.access_management.auth.service;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.user.dto.UserResponse;

public interface AuthService {
  UserResponse register(RegisterRequest req);
  LoginResponse login(LoginRequest req);
  LoginResponse refresh(RefreshRequest req);
  void logout(RefreshRequest req);
  UserResponse me(String email);
}
