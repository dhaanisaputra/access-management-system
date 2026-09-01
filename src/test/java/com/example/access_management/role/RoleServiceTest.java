package com.example.access_management.role;

import com.example.access_management.role.dto.RoleRequest;
import com.example.access_management.role.service.RoleService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class RoleServiceTest {
  @Autowired RoleService roleService;

  @Test void createRole() {
    var r = roleService.create(new RoleRequest("ROLE_TEST", java.util.Set.of()));
    assertThat(r.name()).isEqualTo("ROLE_TEST");
  }
}
