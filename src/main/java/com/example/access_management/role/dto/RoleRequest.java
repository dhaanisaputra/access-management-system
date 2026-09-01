package com.example.access_management.role.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Set;

public record RoleRequest(
    @NotBlank String name,
    Set<Long> permissionIds
) {}
