package com.example.access_management.auth;

import com.example.access_management.auth.repository.OAuthAccountRepository;
import com.example.access_management.auth.service.OAuthAccountService;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
class OAuthAccountServiceTest {

  @Autowired OAuthAccountService service;
  @Autowired OAuthAccountRepository oAuthRepo;
  @Autowired UserRepository userRepo;

  @Test
  void newEmailCreatesUserAndOAuthAccount() {
    User u = service.processOAuthUser("google", "gid-new", "newuser@a.com", "New User");
    assertThat(u.getId()).isNotNull();
    assertThat(u.isEmailVerified()).isTrue();
    assertThat(userRepo.findByEmail("newuser@a.com")).isPresent();
    assertThat(oAuthRepo.findByProviderAndProviderUserId("google", "gid-new")).isPresent();
  }

  @Test
  void secondCallSameProviderUserIdReturnsSameUserNoDuplicate() {
    User first = service.processOAuthUser("google", "gid-dup", "dup2@a.com", "Dup");
    long countBefore = oAuthRepo.count();
    User second = service.processOAuthUser("google", "gid-dup", "other@a.com", "Other");
    assertThat(second.getId()).isEqualTo(first.getId());
    assertThat(oAuthRepo.count()).isEqualTo(countBefore);
    // provider+providerUserId still maps to first email's user
    assertThat(oAuthRepo.findByProviderAndProviderUserId("google", "gid-dup").get().getUser().getId())
        .isEqualTo(first.getId());
  }

  @Test
  void existingEmailNewProviderLinks() {
    User existing = service.processOAuthUser("google", "gid-link1", "link@a.com", "Link User");
    long userCountBefore = userRepo.count();
    User linked = service.processOAuthUser("github", "gh-999", "link@a.com", "Link User");
    assertThat(linked.getId()).isEqualTo(existing.getId());
    assertThat(userRepo.count()).isEqualTo(userCountBefore);
    assertThat(oAuthRepo.findByProviderAndProviderUserId("github", "gh-999")).isPresent();
    assertThat(oAuthRepo.findByUserId(existing.getId())).hasSize(2);
  }
}
