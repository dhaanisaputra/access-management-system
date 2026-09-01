package com.example.access_management.user.dto;

import java.time.Instant;
import java.util.Set;

public record UserResponse(Long id, String email, String fullName, boolean enabled, boolean emailVerified, Instant createdAt, Set<String> roles) {}
