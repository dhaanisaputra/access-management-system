package com.example.access_management.role.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import com.example.access_management.role.service.RoleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

  private final RoleService roleService;

  @PostMapping
  @PreAuthorize("hasAuthority('role:assign')")
  public ResponseEntity<ApiResponse<RoleResponse>> create(@Valid @RequestBody RoleRequest req) {
    return ResponseEntity.status(201).body(ApiResponse.created(roleService.create(req)));
  }

  @GetMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<List<RoleResponse>>> findAll() {
    return ResponseEntity.ok(ApiResponse.ok(roleService.findAll()));
  }
}
