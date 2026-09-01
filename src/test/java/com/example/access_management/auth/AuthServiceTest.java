package com.example.access_management.auth;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.exception.DuplicateResourceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
class AuthServiceTest {

  @Autowired AuthService authService;

  @Test
  void registerAndLogin() {
    var req = new RegisterRequest("test@a.com", "Password123", "Test User");
    var user = authService.register(req);
    assertThat(user.email()).isEqualTo("test@a.com");
    var login = authService.login(new LoginRequest("test@a.com", "Password123"));
    assertThat(login.accessToken()).isNotBlank();
    assertThat(login.refreshToken()).isNotBlank();
  }

  @Test
  void duplicateRegisterThrows409() {
    var req = new RegisterRequest("dup@a.com", "Password123", "Dup");
    authService.register(req);
    assertThatThrownBy(() -> authService.register(req)).isInstanceOf(DuplicateResourceException.class);
  }

  @Test
  void loginWrongPasswordThrows() {
    authService.register(new RegisterRequest("wrong@a.com", "Password123", "W"));
    assertThatThrownBy(() -> authService.login(new LoginRequest("wrong@a.com", "bad"))).isInstanceOf(BusinessException.class);
  }

  @Test
  void refreshRotate() {
    authService.register(new RegisterRequest("ref@a.com", "Password123", "R"));
    var login = authService.login(new LoginRequest("ref@a.com", "Password123"));
    var refreshed = authService.refresh(new RefreshRequest(login.refreshToken()));
    assertThat(refreshed.accessToken()).isNotEqualTo(login.accessToken());
  }
}
