package com.example.access_management.role.dto;

import java.util.Set;

public record RoleResponse(Long id, String name, String description, Set<String> permissions) {}
