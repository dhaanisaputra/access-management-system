package com.example.access_management.role.service;

import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import java.util.List;

public interface RoleService {
  RoleResponse create(RoleRequest req);
  List<RoleResponse> findAll();
}
