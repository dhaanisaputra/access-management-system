package com.example.access_management.role.controller;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequestMapping("/api/v1/roles")
public interface RoleController {

  @PostMapping
  ApiResponse<RoleResponse> create(@Valid @RequestBody RoleRequest req);

  @GetMapping
  ApiResponse<List<RoleResponse>> findAll();
}
