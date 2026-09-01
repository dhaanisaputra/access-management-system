package com.example.access_management.role.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import com.example.access_management.role.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController @RequiredArgsConstructor
public class RoleControllerImpl implements RoleController {

  private final RoleService roleService;

  @Override
  @PreAuthorize("hasAuthority('role:assign')")
  public ApiResponse<RoleResponse> create(RoleRequest req) {
    return ApiResponse.created(roleService.create(req));
  }

  @Override
  @PreAuthorize("hasRole('ADMIN')")
  public ApiResponse<List<RoleResponse>> findAll() {
    return ApiResponse.ok(roleService.findAll());
  }
}
