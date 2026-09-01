package com.example.access_management.auth;

import com.example.access_management.auth.entity.OAuthAccount;
import com.example.access_management.auth.repository.OAuthAccountRepository;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class OAuthAccountRepositoryTest {

  @Autowired OAuthAccountRepository repo;
  @Autowired UserRepository userRepo;

  @Test
  void saveAndFindByProviderAndProviderUserId() {
    User u = userRepo.save(User.builder().email("oauth@a.com").passwordHash("x").fullName("OA").build());
    OAuthAccount acc = repo.save(OAuthAccount.builder().provider("google").providerUserId("gid123").email("oauth@a.com").user(u).build());

    assertThat(acc.getId()).isNotNull();
    assertThat(repo.findByProviderAndProviderUserId("google", "gid123")).isPresent();
    assertThat(repo.findByProviderAndProviderUserId("google", "other")).isEmpty();
  }

  @Test
  void findByEmailAndFindByUserId() {
    User u1 = userRepo.save(User.builder().email("u1@a.com").passwordHash("x").fullName("U1").build());
    User u2 = userRepo.save(User.builder().email("u2@a.com").passwordHash("x").fullName("U2").build());
    repo.save(OAuthAccount.builder().provider("google").providerUserId("gid1").email("shared@a.com").user(u1).build());
    repo.save(OAuthAccount.builder().provider("google").providerUserId("gid2").email("shared@a.com").user(u2).build());

    assertThat(repo.findByEmail("shared@a.com")).hasSize(2);
    assertThat(repo.findByUserId(u1.getId())).hasSize(1);
    assertThat(repo.findByUserId(u1.getId()).get(0).getProviderUserId()).isEqualTo("gid1");
  }
}
