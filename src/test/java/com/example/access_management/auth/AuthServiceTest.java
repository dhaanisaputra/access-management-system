package com.example.access_management.auth;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.repository.UserSessionRepository;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.exception.DuplicateResourceException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
class AuthServiceTest {

  @Autowired AuthService authService;
  @Autowired UserSessionRepository userSessionRepository;

  private void setMockRequest(String ip, String userAgent) {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRemoteAddr(ip);
    req.addHeader("X-Forwarded-For", ip);
    if (userAgent != null) req.addHeader("User-Agent", userAgent);
    RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(req));
  }

  @Test
  void registerAndLogin() {
    var req = new RegisterRequest("test@a.com", "Password123", "Test User");
    var user = authService.register(req);
    assertThat(user.email()).isEqualTo("test@a.com");
    setMockRequest("1.1.1.1", "Mozilla/5.0 Test");
    var login = authService.login(new LoginRequest("test@a.com", "Password123"));
    assertThat(login.accessToken()).isNotBlank();
    assertThat(login.refreshToken()).isNotBlank();
    // risk fields populated
    assertThat(login.riskLevel()).isIn("LOW", "MEDIUM", "HIGH");
    assertThat(login.riskReasons()).isNotNull();
    assertThat(login.riskScore()).isGreaterThanOrEqualTo(0);
    // UserSession saved
    var sessions = userSessionRepository.findByUserId(user.id());
    assertThat(sessions).isNotEmpty();
    assertThat(sessions.get(0).getIpAddress()).isEqualTo("1.1.1.1");
    RequestContextHolder.resetRequestAttributes();
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
    assertThat(refreshed.riskLevel()).isEqualTo("LOW");
    assertThat(refreshed.suspicious()).isFalse();
  }

  @Test
  void suspiciousLoginOnIpChange() {
    var req = new RegisterRequest("susp@a.com", "Password123", "Susp User");
    var user = authService.register(req);
    setMockRequest("1.1.1.1", "Mozilla/5.0 DeviceA");
    var first = authService.login(new LoginRequest("susp@a.com", "Password123"));
    assertThat(first.suspicious()).isFalse();
    assertThat(first.riskScore()).isLessThan(40);

    setMockRequest("9.9.9.9", "Mozilla/5.0 DeviceA");
    var second = authService.login(new LoginRequest("susp@a.com", "Password123"));
    assertThat(second.suspicious()).isTrue();
    assertThat(second.riskScore()).isGreaterThanOrEqualTo(40);
    assertThat(second.riskReasons()).anyMatch(s -> s.contains("IP changed"));
    assertThat(second.riskLevel()).isIn("MEDIUM", "HIGH");

    // verify UserSession for second ip saved
    var sessions = userSessionRepository.findByUserId(user.id());
    assertThat(sessions.stream().anyMatch(s -> "9.9.9.9".equals(s.getIpAddress()))).isTrue();
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  void loginRiskFieldsPresentForUnknownIp() {
    authService.register(new RegisterRequest("risk@a.com", "Password123", "Risk"));
    // no mock request -> ip unknown, should still return risk fields with defaults
    RequestContextHolder.resetRequestAttributes();
    var login = authService.login(new LoginRequest("risk@a.com", "Password123"));
    assertThat(login.riskScore()).isGreaterThanOrEqualTo(0);
    assertThat(login.riskLevel()).isNotNull();
    assertThat(login.riskReasons()).isNotNull();
  }
}
