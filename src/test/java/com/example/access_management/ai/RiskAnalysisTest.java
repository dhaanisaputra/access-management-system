package com.example.access_management.ai;

import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.RoleRepository;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RiskAnalysisTest {

  @Autowired MockMvc mvc;
  @Autowired UserRepository userRepository;
  @Autowired RoleRepository roleRepository;
  @Autowired PasswordEncoder passwordEncoder;

  @BeforeEach
  void ensureUser() {
    if (userRepository.count() == 0) {
      Role role = roleRepository.findByName("ROLE_USER").orElseGet(() ->
          roleRepository.save(Role.builder().name("ROLE_USER").description("Default user").build()));
      User u = User.create("risk-seed@test.com", passwordEncoder.encode("Password123"), "Risk Seed", Set.of(role));
      userRepository.save(u);
    }
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void adminCanAccess() throws Exception {
    String json = mvc.perform(get("/api/v1/admin/risk-analysis"))
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    Integer total = JsonPath.read(json, "$.data.totalUsers");
    assertThat(total).isGreaterThanOrEqualTo(1);
    // topRiskyUsers not null
    Object top = JsonPath.read(json, "$.data.topRiskyUsers");
    assertThat(top).isNotNull();
    Object riskyPerms = JsonPath.read(json, "$.data.riskyPermissions");
    assertThat(riskyPerms).isNotNull();
  }

  @Test
  @WithMockUser(roles = "USER")
  void nonAdminForbidden() throws Exception {
    mvc.perform(get("/api/v1/admin/risk-analysis"))
        .andExpect(status().isForbidden());
  }

  @Test
  void unauthenticatedUnauthorized() throws Exception {
    mvc.perform(get("/api/v1/admin/risk-analysis"))
        .andExpect(status().isUnauthorized());
  }
}
