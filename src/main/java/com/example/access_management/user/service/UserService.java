package com.example.access_management.user.service;

import com.example.access_management.user.dto.UserResponse;

public interface UserService {
  UserResponse getById(Long id);
  UserResponse getByEmail(String email);
}
