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
    User u = User.builder().email("a@b.com").passwordHash("x").fullName("A").build();
    repo.save(u);
    assertThat(repo.existsByEmail("a@b.com")).isTrue();
    assertThat(repo.findByEmailWithRolesAndPermissions("a@b.com")).isPresent();
  }
  @Test void richDomainBehaviors() {
    User u = User.create("rich@b.com", "hash", "Rich", null);
    assertThat(u.isLocked()).isFalse();
    u.recordFailedAttempt(2, 15);
    assertThat(u.getFailedAttempts()).isEqualTo(1);
    u.recordFailedAttempt(2, 15);
    assertThat(u.isLocked()).isTrue();
    u.resetLockout();
    assertThat(u.isLocked()).isFalse();
    assertThat(u.getFailedAttempts()).isEqualTo(0);
  }
}
