package com.example.access_management;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class IntegrationTest {

  @Autowired MockMvc mvc;

  @Test
  void fullFlow() throws Exception {
    // 1. register
    mvc.perform(post("/api/v1/auth/register")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"e2e@a.com\",\"password\":\"Password123\",\"fullName\":\"E2E\"}"))
        .andExpect(status().isCreated());

    // 2. login
    String loginRes = mvc.perform(post("/api/v1/auth/login")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"e2e@a.com\",\"password\":\"Password123\"}"))
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    String access = JsonPath.read(loginRes, "$.data.accessToken");
    String refresh = JsonPath.read(loginRes, "$.data.refreshToken");

    // 3. me
    mvc.perform(get("/api/v1/auth/me")
            .header("Authorization", "Bearer " + access))
        .andExpect(status().isOk());

    // 4. refresh
    mvc.perform(post("/api/v1/auth/refresh")
            .contentType(APPLICATION_JSON)
            .content("{\"refreshToken\":\"" + refresh + "\"}"))
        .andExpect(status().isOk());

    // 5. users without auth -> 401
    mvc.perform(get("/api/v1/users/1"))
        .andExpect(status().isUnauthorized());

    // 6. users with RBAC (has user:read via ROLE_USER)
    mvc.perform(get("/api/v1/users/1")
            .header("Authorization", "Bearer " + access))
        .andExpect(status().isOk());
  }
}
