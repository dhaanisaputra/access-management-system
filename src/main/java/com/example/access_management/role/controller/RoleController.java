package com.example.access_management.role.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import com.example.access_management.role.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "Roles", description = "Role management")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
public class RoleController {

  private final RoleService roleService;

  @Operation(summary = "Create role")
  @PostMapping
  @PreAuthorize("hasAuthority('role:assign')")
  public ResponseEntity<ApiResponse<RoleResponse>> create(@Valid @RequestBody RoleRequest req) {
    return ResponseEntity.status(201).body(ApiResponse.created(roleService.create(req)));
  }

  @Operation(summary = "List all roles")
  @GetMapping
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<ApiResponse<List<RoleResponse>>> findAll() {
    return ResponseEntity.ok(ApiResponse.ok(roleService.findAll()));
  }
}
