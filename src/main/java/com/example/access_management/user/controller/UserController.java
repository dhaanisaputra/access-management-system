package com.example.access_management.user.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/api/v1/users")
public interface UserController {
  @GetMapping("/{id}")
  ApiResponse<UserResponse> getById(@PathVariable Long id);
}
