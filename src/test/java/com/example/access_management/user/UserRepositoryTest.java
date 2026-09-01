package com.example.access_management.user;

import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryTest {
  @Autowired UserRepository repo;
  @Test void existsByEmailWorks() {
    User u = new User(); u.setEmail("a@b.com"); u.setPasswordHash("x"); u.setFullName("A");
    repo.save(u);
    assertThat(repo.existsByEmail("a@b.com")).isTrue();
    assertThat(repo.findByEmailWithRolesAndPermissions("a@b.com")).isPresent();
  }
}
