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
        Permission p = new Permission();
        p.setName(n);
        p.setDescription(n);
        permRepo.save(p);
      }
    }
    if (roleRepo.findByName("ROLE_USER").isEmpty()) {
      Permission read = permRepo.findByName("user:read").orElseThrow();
      Role userRole = new Role();
      userRole.setName("ROLE_USER");
      userRole.setDescription("Default user");
      userRole.setPermissions(Set.of(read));
      roleRepo.save(userRole);
    }
    if (roleRepo.findByName("ROLE_ADMIN").isEmpty()) {
      Role admin = new Role();
      admin.setName("ROLE_ADMIN");
      admin.setDescription("Administrator");
      admin.setPermissions(new HashSet<>(permRepo.findAll()));
      roleRepo.save(admin);
    }
  }
}
