package com.example.access_management.auth;

import com.example.access_management.auth.repository.OAuthAccountRepository;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.security.service.CustomOAuth2SuccessHandler;
import com.example.access_management.user.repository.UserRepository;
import com.jayway.jsonpath.JsonPath;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class OAuth2IntegrationTest {

  @Autowired MockMvc mvc;
  @Autowired CustomOAuth2SuccessHandler successHandler;
  @Autowired UserRepository userRepository;
  @Autowired OAuthAccountRepository oAuthAccountRepository;
  @Autowired JwtService jwtService;
  @Autowired ObjectMapper objectMapper;

  @Test
  void handleCreatesUserAndReturnsTokens() {
    String email = "oauth-int-" + System.nanoTime() + "@a.com";
    var res = successHandler.handle("google", "gid-int-" + System.nanoTime(), email, "Int User");
    assertThat(res.accessToken()).isNotBlank();
    assertThat(res.refreshToken()).isNotBlank();
    assertThat(jwtService.validateToken(res.accessToken())).isTrue();
    assertThat(userRepository.findByEmail(email)).isPresent();
  }

  @Test
  void onAuthenticationSuccessWritesJsonWithTokensAndCreatesUser() throws Exception {
    String email = "oauth-success-" + System.nanoTime() + "@a.com";
    String sub = "sub-" + System.nanoTime();
    OAuth2AuthenticationToken token = oauthToken("google", sub, email, "Success User");

    MockHttpServletRequest req = new MockHttpServletRequest();
    MockHttpServletResponse resp = new MockHttpServletResponse();

    successHandler.onAuthenticationSuccess(req, resp, token);

    assertThat(resp.getStatus()).isEqualTo(200);
    assertThat(resp.getContentType()).contains("application/json");
    String body = resp.getContentAsString();
    String access = JsonPath.read(body, "$.data.accessToken");
    String refresh = JsonPath.read(body, "$.data.refreshToken");
    assertThat(access).isNotBlank();
    assertThat(refresh).isNotBlank();
    assertThat(jwtService.validateToken(access)).isTrue();
    assertThat(userRepository.findByEmail(email)).isPresent();
    assertThat(oAuthAccountRepository.findByProviderAndProviderUserId("google", sub)).isPresent();
  }

  @Test
  void onAuthenticationSuccessUsesSubFallbackAndHandlesMissingName() throws Exception {
    String sub = "sub-fallback-" + System.nanoTime();
    OAuth2AuthenticationToken token = oauthToken("google", sub, "fallback-" + System.nanoTime() + "@a.com", null);
    MockHttpServletRequest req = new MockHttpServletRequest();
    MockHttpServletResponse resp = new MockHttpServletResponse();
    successHandler.onAuthenticationSuccess(req, resp, token);
    assertThat(resp.getStatus()).isEqualTo(200);
    String body = resp.getContentAsString();
    assertThat(JsonPath.<String>read(body, "$.data.accessToken")).isNotBlank();
  }

  @Test
  void oauth2EndpointsPermitAllAndExistingAuthStillSecured() throws Exception {
    // Spring OAuth2 endpoints should not return 401
    mvc.perform(get("/oauth2/authorization/google"))
        .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401));
    mvc.perform(get("/login/oauth2/code/google"))
        .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(401));

    // existing auth still works: unauthenticated me -> 401
    mvc.perform(get("/api/v1/auth/me"))
        .andExpect(status().isUnauthorized());

    // login still permitAll (will be 400/401 due to bad body, but not 403)
    mvc.perform(post("/api/v1/auth/login")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"no@a.com\",\"password\":\"x\"}"))
        .andExpect(result -> assertThat(result.getResponse().getStatus()).isNotEqualTo(403));
  }

  @Test
  void loginRegisterStillWork() throws Exception {
    String email = "oauth-reg-" + System.nanoTime() + "@a.com";
    mvc.perform(post("/api/v1/auth/register")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"" + email + "\",\"password\":\"Password123\",\"fullName\":\"Reg\"}"))
        .andExpect(status().isCreated());
    String loginRes = mvc.perform(post("/api/v1/auth/login")
            .contentType(APPLICATION_JSON)
            .content("{\"email\":\"" + email + "\",\"password\":\"Password123\"}"))
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();
    assertThat(JsonPath.<String>read(loginRes, "$.data.accessToken")).isNotBlank();
  }

  private static OAuth2AuthenticationToken oauthToken(String provider, String sub, String email, String name) {
    Map<String, Object> attrs = new HashMap<>();
    attrs.put("sub", sub);
    attrs.put("email", email);
    if (name != null) attrs.put("name", name);
    OAuth2User principal = new DefaultOAuth2User(Collections.emptyList(), attrs, "sub");
    return new OAuth2AuthenticationToken(principal, Collections.emptyList(), provider);
  }
}
