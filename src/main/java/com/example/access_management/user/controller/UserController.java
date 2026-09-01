package com.example.access_management.user.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('user:read')")
  public ResponseEntity<ApiResponse<UserResponse>> getById(@PathVariable Long id) {
    return ResponseEntity.ok(ApiResponse.ok(userService.getById(id)));
  }
}
