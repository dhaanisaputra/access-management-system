package com.example.access_management.common.dto;

import java.time.Instant;

public record ApiResponse<T>(boolean success, String message, T data, Instant timestamp) {
  public static <T> ApiResponse<T> ok(T data) {
    return new ApiResponse<>(true, "Success", data, Instant.now());
  }
  public static <T> ApiResponse<T> created(T data) {
    return new ApiResponse<>(true, "Created", data, Instant.now());
  }
  public static <T> ApiResponse<T> ok(T data, String msg) {
    return new ApiResponse<>(true, msg, data, Instant.now());
  }
}
