package com.example.access_management.auth;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutBlacklistTest {

  @Autowired MockMvc mvc;
  @Autowired AuthService authService;

  @Test
  void logout_blacklistsAccessToken_thenMeReturns401() throws Exception {
    String email = "logout-blacklist@test.com";
    authService.register(new RegisterRequest(email, "Password123", "Logout Test"));
    var login = authService.login(new LoginRequest(email, "Password123"));
    String access = login.accessToken();
    String refresh = login.refreshToken();

    // logout with Authorization header -> should blacklist access jti
    mvc.perform(post("/api/v1/auth/logout")
            .header("Authorization", "Bearer " + access)
            .contentType(APPLICATION_JSON)
            .content("{\"refreshToken\":\"" + refresh + "\"}"))
        .andExpect(status().isOk());

    // next request with same access token should be 401 due to blacklist
    mvc.perform(get("/api/v1/auth/me")
            .header("Authorization", "Bearer " + access))
        .andExpect(status().isUnauthorized());

    // refresh token also revoked -> refresh should fail
    mvc.perform(post("/api/v1/auth/refresh")
            .contentType(APPLICATION_JSON)
            .content("{\"refreshToken\":\"" + refresh + "\"}"))
        .andExpect(status().is4xxClientError());
  }

  @Test
  void logout_withoutAuthHeader_stillRevokesRefresh() throws Exception {
    String email = "logout-noheader@test.com";
    authService.register(new RegisterRequest(email, "Password123", "NoHeader"));
    var login = authService.login(new LoginRequest(email, "Password123"));
    String refresh = login.refreshToken();

    mvc.perform(post("/api/v1/auth/logout")
            .contentType(APPLICATION_JSON)
            .content("{\"refreshToken\":\"" + refresh + "\"}"))
        .andExpect(status().isOk());

    mvc.perform(post("/api/v1/auth/refresh")
            .contentType(APPLICATION_JSON)
            .content("{\"refreshToken\":\"" + refresh + "\"}"))
        .andExpect(status().is4xxClientError());
  }
}
