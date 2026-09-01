package com.example.access_management.common.util;

import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.entity.User;
import java.util.stream.Collectors;

public final class MapperUtil {
  private MapperUtil() {}

  public static UserResponse toUserResponse(User u) {
    return new UserResponse(
        u.getId(),
        u.getEmail(),
        u.getFullName(),
        u.isEnabled(),
        u.isEmailVerified(),
        u.getCreatedAt(),
        u.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet())
    );
  }
}
