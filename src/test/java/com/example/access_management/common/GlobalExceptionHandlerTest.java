package com.example.access_management.common;

import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.exception.DuplicateResourceException;
import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {
  @Test void apiResponseOk() {
    ApiResponse<String> r = ApiResponse.ok("hello");
    assertThat(r.success()).isTrue();
    assertThat(r.data()).isEqualTo("hello");
  }
  @Test void resourceNotFoundMapsTo404() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleNotFound(new ResourceNotFoundException("User not found"));
    assertThat(resp.getStatusCode().value()).isEqualTo(404);
    assertThat(resp.getBody().success()).isFalse();
  }
  @Test void duplicateMapsTo409() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleDuplicate(new DuplicateResourceException("Email exists"));
    assertThat(resp.getStatusCode().value()).isEqualTo(409);
  }
  @Test void businessMapsTo400() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleBusiness(new BusinessException("Invalid credentials"));
    assertThat(resp.getStatusCode().value()).isEqualTo(400);
  }
}
