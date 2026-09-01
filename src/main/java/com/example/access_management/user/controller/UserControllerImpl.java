package com.example.access_management.user.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserControllerImpl implements UserController {
  private final UserService userService;

  @Override
  @PreAuthorize("hasAuthority('user:read')")
  public ApiResponse<UserResponse> getById(Long id) {
    return ApiResponse.ok(userService.getById(id));
  }
}
