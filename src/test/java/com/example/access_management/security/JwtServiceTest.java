package com.example.access_management.security;

import com.example.access_management.role.entity.Permission;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.PermissionRepository;
import com.example.access_management.role.repository.RoleRepository;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtServiceTest {

  @Autowired JwtService jwtService;
  @Autowired UserRepository userRepo;
  @Autowired RoleRepository roleRepo;
  @Autowired PermissionRepository permRepo;

  @Test
  @Transactional
  void generateAndValidate() {
    Permission perm = permRepo.save(Permission.builder().name("jwt_perm_" + System.nanoTime()).description("read").build());
    Role role = Role.builder().name("ROLE_JWT_" + System.nanoTime()).description("user").permissions(Set.of(perm)).build();
    role = roleRepo.save(role);

    User u = User.builder().email("jwt@b.com").passwordHash("x").fullName("J").roles(Set.of(role)).build();
    u = userRepo.save(u);

    String token = jwtService.generateAccessToken(u);
    assertThat(jwtService.validateToken(token)).isTrue();
    assertThat(jwtService.extractEmail(token)).isEqualTo("jwt@b.com");
  }

  @Test
  @Transactional
  void extractEmailAndUserId() {
    Permission perm = permRepo.save(Permission.builder().name("jwt_perm2_" + System.nanoTime()).description("read2").build());
    Role role = Role.builder().name("ROLE_JWT2_" + System.nanoTime()).description("user2").permissions(Set.of(perm)).build();
    role = roleRepo.save(role);

    User u = User.builder().email("jwt2@b.com").passwordHash("x").fullName("J2").roles(Set.of(role)).build();
    u = userRepo.save(u);

    String token = jwtService.generateAccessToken(u);
    assertThat(jwtService.extractEmail(token)).isEqualTo("jwt2@b.com");
    assertThat(jwtService.extractUserId(token)).isEqualTo(u.getId());
    assertThat(jwtService.validateToken("invalid.token.here")).isFalse();
  }
}
