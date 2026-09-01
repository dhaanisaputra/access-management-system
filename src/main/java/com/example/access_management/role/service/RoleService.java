package com.example.access_management.role.service;

import com.example.access_management.common.exception.DuplicateResourceException;
import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.dto.RoleResponse;
import com.example.access_management.role.entity.Permission;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.PermissionRepository;
import com.example.access_management.role.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService {

  private final RoleRepository roleRepository;
  private final PermissionRepository permissionRepository;

  @Transactional
  public RoleResponse create(RoleRequest req) {
    log.debug("create role {}", req.name());
    if (roleRepository.existsByName(req.name())) {
      throw new DuplicateResourceException("Role already exists: " + req.name());
    }
    Set<Permission> perms = new HashSet<>();
    if (req.permissionIds() != null && !req.permissionIds().isEmpty()) {
      perms.addAll(permissionRepository.findAllById(req.permissionIds()));
    }
    Role role = Role.builder()
        .name(req.name())
        .permissions(perms)
        .build();
    role = roleRepository.save(role);
    return toResponse(role);
  }

  @Transactional(readOnly = true)
  public List<RoleResponse> findAll() {
    return roleRepository.findAll().stream().map(this::toResponse).toList();
  }

  private RoleResponse toResponse(Role r) {
    Set<String> permNames = r.getPermissions() == null ? Set.of()
        : r.getPermissions().stream().map(Permission::getName).collect(Collectors.toSet());
    return new RoleResponse(r.getId(), r.getName(), r.getDescription(), permNames);
  }
}
