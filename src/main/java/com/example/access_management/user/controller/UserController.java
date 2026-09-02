package com.example.access_management.user.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Users", description = "User management")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;

  @Operation(summary = "Get user by ID")
  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('user:read')")
  public ResponseEntity<ApiResponse<UserResponse>> getById(@PathVariable Long id) {
    return ResponseEntity.ok(ApiResponse.ok(userService.getById(id)));
  }
}
