package com.example.access_management.common.config;

import com.example.access_management.role.entity.Permission;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.PermissionRepository;
import com.example.access_management.role.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

  private final PermissionRepository permRepo;
  private final RoleRepository roleRepo;

  @Override
  @Transactional
  public void run(String... args) {
    List<String> requiredPerms = List.of(
        "user:create", "user:read", "user:update", "user:delete", "role:assign", "role:read");
    for (String n : requiredPerms) {
      if (permRepo.findByName(n).isEmpty()) {
        Permission p = Permission.builder().name(n).description(n).build();
        permRepo.save(p);
      }
    }
    if (roleRepo.findByName("ROLE_USER").isEmpty()) {
      Permission read = permRepo.findByName("user:read").orElseThrow();
      Role userRole = Role.builder().name("ROLE_USER").description("Default user").permissions(Set.of(read)).build();
      roleRepo.save(userRole);
    }
    if (roleRepo.findByName("ROLE_ADMIN").isEmpty()) {
      Role admin = Role.builder().name("ROLE_ADMIN").description("Administrator").permissions(new HashSet<>(permRepo.findAll())).build();
      roleRepo.save(admin);
    }
  }
}
