package com.example.access_management.auth;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.repository.LoginAttemptRepository;
import com.example.access_management.auth.service.AuthService;
import com.example.access_management.common.exception.BusinessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class LoginAttemptTest {

  @Autowired AuthService authService;
  @Autowired LoginAttemptRepository loginAttemptRepository;

  @BeforeEach
  void clean() {
    loginAttemptRepository.deleteAll();
  }

  private void awaitCount(String email, boolean success, long expected) throws Exception {
    long deadline = System.currentTimeMillis() + 3000;
    while (System.currentTimeMillis() < deadline) {
      long cnt = loginAttemptRepository.findByEmail(email).stream().filter(a -> a.isSuccess() == success).count();
      if (cnt >= expected) return;
      Thread.sleep(100);
    }
  }

  @Test
  void loginFail_recordsAttemptWithSuccessFalse() throws Exception {
    String email = "attempt-fail@test.com";
    authService.register(new RegisterRequest(email, "Password123", "Attempt Fail"));

    assertThatThrownBy(() -> authService.login(new LoginRequest(email, "wrongPass")))
        .isInstanceOf(BusinessException.class);

    awaitCount(email, false, 1);
    long failCount = loginAttemptRepository.findByEmail(email).stream().filter(a -> !a.isSuccess()).count();
    assertThat(failCount).isGreaterThanOrEqualTo(1);
    var attempt = loginAttemptRepository.findByEmail(email).stream().filter(a -> !a.isSuccess()).findFirst().orElseThrow();
    assertThat(attempt.getIpAddress()).isNotBlank();
    assertThat(attempt.getAttemptedAt()).isNotNull();
  }

  @Test
  void loginSuccess_recordsAttemptWithSuccessTrue() throws Exception {
    String email = "attempt-success@test.com";
    authService.register(new RegisterRequest(email, "Password123", "Attempt Success"));

    var resp = authService.login(new LoginRequest(email, "Password123"));
    assertThat(resp.accessToken()).isNotBlank();

    awaitCount(email, true, 1);
    long successCount = loginAttemptRepository.findByEmail(email).stream().filter(a -> a.isSuccess()).count();
    assertThat(successCount).isGreaterThanOrEqualTo(1);
  }

  @Test
  void loginFail_thenSuccess_countsBoth() throws Exception {
    String email = "attempt-both@test.com";
    authService.register(new RegisterRequest(email, "Password123", "Both"));

    assertThatThrownBy(() -> authService.login(new LoginRequest(email, "bad")))
        .isInstanceOf(BusinessException.class);
    authService.login(new LoginRequest(email, "Password123"));

    awaitCount(email, true, 1);
    // wait a bit more for fail to be persisted
    Thread.sleep(200);
    var all = loginAttemptRepository.findByEmail(email);
    assertThat(all.stream().filter(a -> !a.isSuccess()).count()).isGreaterThanOrEqualTo(1);
    assertThat(all.stream().filter(a -> a.isSuccess()).count()).isGreaterThanOrEqualTo(1);
  }
}
