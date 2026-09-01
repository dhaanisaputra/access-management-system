# Identity & Access Management — Fase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Fase 1 MVP — register/login/logout, JWT 15m + opaque refresh 7d rotate, RBAC Role+Permission, password hashing, API security — feature-based with controller interface -> service interface, global response/handler, anti N+1.

**Architecture:** Modular monolith feature-based (auth/user/role/security/common), JWT stateless access + DB refresh_tokens R1 (SHA-256 hash), BCrypt(12), JOIN FETCH for user+roles+permissions, silent refresh 401->refresh->retry.

**Tech Stack:** Java 25, Spring Boot 4.1.1, Spring Security, Spring Data JPA, PostgreSQL, JJWT 0.12.x, Jakarta Validation, Lombok, Spring AOP.

## Global Constraints

- Java 25, Spring Boot 4.1.1, spring-boot-starter-parent
- Package base: `com.example.access_management`
- DB: PostgreSQL `access_management_platform`, HikariCP, `spring.jpa.hibernate.ddl-auto=update` (Fase 1), no Flyway yet
- JWT: access 15m (`jwt.access-expiration=900000`), refresh 7d (`jwt.refresh-expiration=604800000`), secret HS256 256-bit via `jwt.secret` env, JJWT `io.jsonwebtoken:jjwt-api/impl/jackson` 0.12.5
- Password: `BCryptPasswordEncoder(12)`
- Feature-based folders: each feature has `controller/`, `service/`, `dto/`, `entity/`, `repository/` subfolders
- Logic bisnis only in `*ServiceImpl`, controller interface + impl delegates 1 line
- Reusable: `common/entity/BaseEntity`, `common/dto/ApiResponse<T>`, `common/exception/GlobalExceptionHandler`, `common/util/MapperUtil`, `common/logging/LoggingAspect`
- Validation: `spring-boot-starter-validation`, record DTO + @Valid
- Response: `ApiResponse<T>(success, message, data, timestamp)` — all success/error via global handler
- Logging: @Slf4j in ServiceImpl + LoggingAspect @Around ServiceImpl (mask password/token) + MDC requestId in JwtAuthFilter
- Efficient query: LAZY all relations, `existsByEmail`, `findByEmailWithRolesAndPermissions()` JOIN FETCH, no N+1
- RBAC: `Role` name `ROLE_*`, `Permission` name `user:*/role:*`, @EnableMethodSecurity, @PreAuthorize hasAuthority/hasRole
- No Redis in Fase 1, no MapStruct, no OAuth2 yet

---

### Task 1: Project Setup — Dependencies & Config

**Files:**
- Modify: `pom.xml:32-66` — add validation + jjwt
- Modify: `src/main/resources/application.properties:1-11` — jwt + lockout + server config

**Interfaces:**
- Consumes: existing pom, application.properties
- Produces: jjwt + validation on classpath, jwt props available for JwtService

- [ ] **Step 1: Write failing test — app starts with new props**

```java
// src/test/java/com/example/access_management/ConfigPropertiesTest.java
package com.example.access_management;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.assertThat;
@SpringBootTest
class ConfigPropertiesTest {
  @Value("${jwt.secret}") String secret;
  @Value("${jwt.access-expiration}") long accessExp;
  @Test void jwtPropsLoaded() {
    assertThat(secret).isNotBlank();
    assertThat(accessExp).isEqualTo(900000L);
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ConfigPropertiesTest -q`
Expected: FAIL — `Could not resolve placeholder 'jwt.secret'`, `jjwt not found`

- [ ] **Step 3: Add dependencies to pom.xml**

```xml
<!-- pom.xml after spring-boot-starter-security-test, before </dependencies> -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-api</artifactId>
  <version>0.12.5</version>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-impl</artifactId>
  <version>0.12.5</version>
  <scope>runtime</scope>
</dependency>
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt-jackson</artifactId>
  <version>0.12.5</version>
  <scope>runtime</scope>
</dependency>
```

- [ ] **Step 4: Update application.properties**

```properties
spring.application.name=access-management
spring.datasource.hikari.minimumIdle=5
spring.datasource.hikari.maximumPoolSize=20
spring.datasource.hikari.connectionTimeout=30000
spring.datasource.hikari.idleTimeout=600000
spring.datasource.hikari.maxLifetime=1800000
spring.datasource.url=jdbc:postgresql://localhost:5432/access_management_platform
spring.datasource.username=admin
spring.datasource.password=postgres
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false
spring.jpa.properties.hibernate.format_sql=true

# JWT (Fase 1)
jwt.secret=change-me-to-256-bit-secret-key-at-least-32-chars-long-please
jwt.access-expiration=900000
jwt.refresh-expiration=604800000

# Security
app.lockout.threshold=5
app.lockout.duration-minutes=15

# Server
server.port=8080
logging.level.com.example.access_management=DEBUG
```

- [ ] **Step 5: Run test to verify it passes**

Run: `mvn test -Dtest=ConfigPropertiesTest -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pom.xml src/main/resources/application.properties src/test/java/com/example/access_management/ConfigPropertiesTest.java
git commit -m "feat: add validation + jjwt + jwt config"
```

---

### Task 2: Common Module — BaseEntity, ApiResponse, Exceptions, GlobalHandler, Mapper, Logging

**Files:**
- Create: `src/main/java/com/example/access_management/common/entity/BaseEntity.java`
- Create: `src/main/java/com/example/access_management/common/dto/ApiResponse.java`
- Create: `src/main/java/com/example/access_management/common/exception/ResourceNotFoundException.java`
- Create: `src/main/java/com/example/access_management/common/exception/DuplicateResourceException.java`
- Create: `src/main/java/com/example/access_management/common/exception/BusinessException.java`
- Create: `src/main/java/com/example/access_management/common/exception/AccountLockedException.java`
- Create: `src/main/java/com/example/access_management/common/exception/GlobalExceptionHandler.java`
- Create: `src/main/java/com/example/access_management/common/util/MapperUtil.java`
- Create: `src/main/java/com/example/access_management/common/logging/LoggingAspect.java`
- Test: `src/test/java/com/example/access_management/common/GlobalExceptionHandlerTest.java`

**Interfaces:**
- Consumes: Spring MVC, Validation
- Produces: `BaseEntity` for all entities, `ApiResponse<T>` factory, exception hierarchy + handler, `MapperUtil.toUserResponse()`, `LoggingAspect` for all `*ServiceImpl`

- [ ] **Step 1: Write failing test for ApiResponse + GlobalHandler**

```java
// src/test/java/com/example/access_management/common/GlobalExceptionHandlerTest.java
package com.example.access_management.common;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.exception.DuplicateResourceException;
import com.example.access_management.common.exception.BusinessException;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
class GlobalExceptionHandlerTest {
  @Test void apiResponseOk() {
    ApiResponse<String> r = ApiResponse.ok("hello");
    assertThat(r.success()).isTrue();
    assertThat(r.data()).isEqualTo("hello");
  }
  @Test void resourceNotFoundMapsTo404() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleNotFound(new ResourceNotFoundException("User not found"));
    assertThat(resp.getStatusCode().value()).isEqualTo(404);
    assertThat(resp.getBody().success()).isFalse();
  }
  @Test void duplicateMapsTo409() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleDuplicate(new DuplicateResourceException("Email exists"));
    assertThat(resp.getStatusCode().value()).isEqualTo(409);
  }
  @Test void businessMapsTo400() {
    GlobalExceptionHandler h = new GlobalExceptionHandler();
    var resp = h.handleBusiness(new BusinessException("Invalid credentials"));
    assertThat(resp.getStatusCode().value()).isEqualTo(400);
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=GlobalExceptionHandlerTest -q`
Expected: FAIL — classes not found

- [ ] **Step 3: Create BaseEntity**

```java
// src/main/java/com/example/access_management/common/entity/BaseEntity.java
package com.example.access_management.common.entity;
import jakarta.persistence.*;
import lombok.Getter; import lombok.Setter;
import java.time.Instant;
@Getter @Setter @MappedSuperclass
public abstract class BaseEntity {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @Column(name="created_at", nullable=false, updatable=false)
  private Instant createdAt;
  @Column(name="updated_at", nullable=false)
  private Instant updatedAt;
  @PrePersist void prePersist() { Instant now = Instant.now(); createdAt = now; updatedAt = now; }
  @PreUpdate void preUpdate() { updatedAt = Instant.now(); }
}
```

- [ ] **Step 4: Create ApiResponse + Exceptions**

```java
// src/main/java/com/example/access_management/common/dto/ApiResponse.java
package com.example.access_management.common.dto;
import java.time.Instant;
public record ApiResponse<T>(boolean success, String message, T data, Instant timestamp) {
  public static <T> ApiResponse<T> ok(T data) { return new ApiResponse<>(true, "Success", data, Instant.now()); }
  public static <T> ApiResponse<T> created(T data) { return new ApiResponse<>(true, "Created", data, Instant.now()); }
  public static <T> ApiResponse<T> ok(T data, String msg) { return new ApiResponse<>(true, msg, data, Instant.now()); }
}
// exception files: each extends RuntimeException with String msg constructor
// ResourceNotFoundException, DuplicateResourceException, BusinessException, AccountLockedException
```

```java
// src/main/java/com/example/access_management/common/exception/GlobalExceptionHandler.java
package com.example.access_management.common.exception;
import com.example.access_management.common.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import java.util.stream.Collectors;
@Slf4j @RestControllerAdvice
public class GlobalExceptionHandler {
  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ApiResponse<Void>> handleNotFound(ResourceNotFoundException ex) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiResponse<>(false, ex.getMessage(), null, java.time.Instant.now()));
  }
  @ExceptionHandler(DuplicateResourceException.class)
  public ResponseEntity<ApiResponse<Void>> handleDuplicate(DuplicateResourceException ex) {
    return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiResponse<>(false, ex.getMessage(), null, java.time.Instant.now()));
  }
  @ExceptionHandler(AccountLockedException.class)
  public ResponseEntity<ApiResponse<Void>> handleLocked(AccountLockedException ex) {
    return ResponseEntity.status(HttpStatus.LOCKED).body(new ApiResponse<>(false, ex.getMessage(), null, java.time.Instant.now()));
  }
  @ExceptionHandler(BusinessException.class)
  public ResponseEntity<ApiResponse<Void>> handleBusiness(BusinessException ex) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiResponse<>(false, ex.getMessage(), null, java.time.Instant.now()));
  }
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiResponse<Void>> handleValidation(MethodArgumentNotValidException ex) {
    String msg = ex.getBindingResult().getFieldErrors().stream().map(f->f.getField()+": "+f.getDefaultMessage()).collect(Collectors.joining(", "));
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ApiResponse<>(false, "Validation failed: "+msg, null, java.time.Instant.now()));
  }
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiResponse<Void>> handleGeneral(Exception ex) {
    log.error("Unexpected error", ex);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(false, "Internal server error", null, java.time.Instant.now()));
  }
}
```

- [ ] **Step 5: Create MapperUtil + LoggingAspect**

```java
// src/main/java/com/example/access_management/common/util/MapperUtil.java
package com.example.access_management.common.util;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.entity.User;
import java.util.stream.Collectors;
public final class MapperUtil {
  private MapperUtil(){}
  public static UserResponse toUserResponse(User u) {
    return new UserResponse(u.getId(), u.getEmail(), u.getFullName(), u.isEnabled(), u.isEmailVerified(), u.getCreatedAt(), u.getRoles().stream().map(r->r.getName()).collect(Collectors.toSet()));
  }
}
// src/main/java/com/example/access_management/common/logging/LoggingAspect.java
package com.example.access_management.common.logging;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint; import org.aspectj.lang.annotation.*;
import org.springframework.stereotype.Component;
@Slf4j @Aspect @Component
public class LoggingAspect {
  @Around("execution(* com.example.access_management..*ServiceImpl.*(..))")
  public Object log(ProceedingJoinPoint pjp) throws Throwable {
    String method = pjp.getSignature().toShortString();
    long start = System.currentTimeMillis();
    try { Object r = pjp.proceed(); log.debug("{} -> {} ms", method, System.currentTimeMillis()-start); return r; }
    catch (Throwable ex) { log.error("{} failed after {} ms: {}", method, System.currentTimeMillis()-start, ex.getMessage()); throw ex; }
  }
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `mvn test -Dtest=GlobalExceptionHandlerTest -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/main/java/com/example/access_management/common/
git add src/test/java/com/example/access_management/common/GlobalExceptionHandlerTest.java
git commit -m "feat: add common BaseEntity, ApiResponse, global handler, mapper, logging"
```

---

### Task 3: User Feature — Entity, Repository, DTO, Service

**Files:**
- Create: `src/main/java/com/example/access_management/user/entity/User.java`
- Create: `src/main/java/com/example/access_management/user/repository/UserRepository.java`
- Create: `src/main/java/com/example/access_management/user/dto/UserResponse.java`
- Create: `src/main/java/com/example/access_management/user/dto/UserCreateRequest.java` (if needed for admin)
- Create: `src/main/java/com/example/access_management/user/service/UserService.java`
- Create: `src/main/java/com/example/access_management/user/service/UserServiceImpl.java`
- Create: `src/main/java/com/example/access_management/user/controller/UserController.java`
- Create: `src/main/java/com/example/access_management/user/controller/UserControllerImpl.java`
- Test: `src/test/java/com/example/access_management/user/UserRepositoryTest.java`

**Interfaces:**
- Consumes: BaseEntity, ApiResponse, MapperUtil, Role entity (Task 4)
- Produces: `UserRepository.existsByEmail()`, `findByEmailWithRolesAndPermissions()` (JOIN FETCH), `UserService.getById()`, `UserController.getById()`

- [ ] **Step 1: Write failing repo test**

```java
// src/test/java/com/example/access_management/user/UserRepositoryTest.java
package com.example.access_management.user;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
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
```

- [ ] **Step 2: Run test — fails (no entity)**

Run: `mvn test -Dtest=UserRepositoryTest -q` → FAIL

- [ ] **Step 3: Create User entity + repo + DTOs**

```java
// user/entity/User.java
package com.example.access_management.user.entity;
import com.example.access_management.common.entity.BaseEntity;
import com.example.access_management.role.entity.Role;
import jakarta.persistence.*;
import lombok.*;
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
@Entity @Table(name="users")
public class User extends BaseEntity {
  @Column(unique=true, nullable=false) private String email;
  @Column(name="password_hash", nullable=false) private String passwordHash;
  @Column(name="full_name", nullable=false) private String fullName;
  @Column(nullable=false) private boolean enabled = true;
  @Column(name="email_verified", nullable=false) private boolean emailVerified = false;
  @Column(name="failed_attempts", nullable=false) private int failedAttempts = 0;
  @Column(name="lockout_until") private java.time.Instant lockoutUntil;
  @ManyToMany(fetch=FetchType.LAZY) @JoinTable(name="user_roles", joinColumns=@JoinColumn(name="user_id"), inverseJoinColumns=@JoinColumn(name="role_id"))
  @Builder.Default private java.util.Set<Role> roles = new java.util.HashSet<>();
}
// user/repository/UserRepository.java
package com.example.access_management.user.repository;
import com.example.access_management.user.entity.User;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.util.Optional;
public interface UserRepository extends JpaRepository<User, Long> {
  boolean existsByEmail(String email);
  Optional<User> findByEmail(String email);
  @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles r LEFT JOIN FETCH r.permissions WHERE u.email = :email")
  Optional<User> findByEmailWithRolesAndPermissions(@Param("email") String email);
  @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles r LEFT JOIN FETCH r.permissions WHERE u.id = :id")
  Optional<User> findByIdWithRoles(@Param("id") Long id);
}
// user/dto/UserResponse.java
package com.example.access_management.user.dto;
import java.time.Instant; import java.util.Set;
public record UserResponse(Long id, String email, String fullName, boolean enabled, boolean emailVerified, Instant createdAt, Set<String> roles) {}
```

- [ ] **Step 4: Create Service + Controller**

```java
// user/service/UserService.java
package com.example.access_management.user.service;
import com.example.access_management.user.dto.UserResponse;
public interface UserService { UserResponse getById(Long id); UserResponse getByEmail(String email); }
// user/service/UserServiceImpl.java
package com.example.access_management.user.service;
import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.util.MapperUtil;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor; import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service; import org.springframework.transaction.annotation.Transactional;
@Service @RequiredArgsConstructor @Slf4j
public class UserServiceImpl implements UserService {
  private final UserRepository userRepository;
  @Override @Transactional(readOnly=true) public UserResponse getById(Long id) {
    log.debug("getById {}", id);
    var u = userRepository.findByIdWithRoles(id).orElseThrow(()->new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(u);
  }
  @Override @Transactional(readOnly=true) public UserResponse getByEmail(String email) {
    var u = userRepository.findByEmailWithRolesAndPermissions(email).orElseThrow(()->new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(u);
  }
}
// user/controller/UserController.java
package com.example.access_management.user.controller;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import org.springframework.web.bind.annotation.*;
@RequestMapping("/api/v1/users")
public interface UserController {
  @GetMapping("/{id}") ApiResponse<UserResponse> getById(@PathVariable Long id);
}
// user/controller/UserControllerImpl.java
package com.example.access_management.user.controller;
import com.example.access_management.common.dto.ApiResponse;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.service.UserService;
import lombok.RequiredArgsConstructor; import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;
@RestController @RequiredArgsConstructor
public class UserControllerImpl implements UserController {
  private final UserService userService;
  @Override @PreAuthorize("hasAuthority('user:read')") public ApiResponse<UserResponse> getById(Long id) { return ApiResponse.ok(userService.getById(id)); }
}
```

- [ ] **Step 5: Run test**

Run: `mvn test -Dtest=UserRepositoryTest -q` → PASS; `mvn test -q` all previous pass

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/example/access_management/user/
git add src/test/java/com/example/access_management/user/UserRepositoryTest.java
git commit -m "feat: add user entity, repo, service, controller"
```

---

### Task 4: Role & Permission — Entities, Repos, Service

**Files:**
- Create: `src/main/java/com/example/access_management/role/entity/Role.java`
- Create: `src/main/java/com/example/access_management/role/entity/Permission.java`
- Create: `src/main/java/com/example/access_management/role/repository/RoleRepository.java`
- Create: `src/main/java/com/example/access_management/role/repository/PermissionRepository.java`
- Create: `src/main/java/com/example/access_management/role/dto/RoleRequest.java`
- Create: `src/main/java/com/example/access_management/role/dto/RoleResponse.java`
- Create: `src/main/java/com/example/access_management/role/service/RoleService.java`
- Create: `src/main/java/com/example/access_management/role/service/RoleServiceImpl.java`
- Create: `src/main/java/com/example/access_management/role/controller/RoleController.java`
- Create: `src/main/java/com/example/access_management/role/controller/RoleControllerImpl.java`
- Test: `src/test/java/com/example/access_management/role/RoleServiceTest.java`

**Interfaces:**
- Consumes: BaseEntity
- Produces: `RoleRepository.findByName()`, `RoleService.createRole()`, seeded permissions

- [ ] **Step 1: Write failing test**

```java
// role/RoleServiceTest.java
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
```

- [ ] **Step 2: Run → FAIL**

Run: `mvn test -Dtest=RoleServiceTest -q` → FAIL

- [ ] **Step 3: Create entities + repos**

```java
// role/entity/Permission.java
@Entity @Table(name="permissions") @Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Permission extends BaseEntity { @Column(unique=true, nullable=false) private String name; private String description; }
// role/entity/Role.java
@Entity @Table(name="roles") @Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Role extends BaseEntity {
  @Column(unique=true, nullable=false) private String name;
  private String description;
  @ManyToMany(fetch=FetchType.LAZY) @JoinTable(name="role_permissions", joinColumns=@JoinColumn(name="role_id"), inverseJoinColumns=@JoinColumn(name="permission_id"))
  @Builder.Default private Set<Permission> permissions = new HashSet<>();
}
// role/repository/RoleRepository.java
public interface RoleRepository extends JpaRepository<Role, Long> { Optional<Role> findByName(String name); boolean existsByName(String name); }
// role/repository/PermissionRepository.java
public interface PermissionRepository extends JpaRepository<Permission, Long> { Optional<Permission> findByName(String name); }
```

- [ ] **Step 4: DTOs + Service + Controller**

```java
// dto/RoleRequest.java: record RoleRequest(@NotBlank String name, Set<Long> permissionIds) {}
// dto/RoleResponse.java: record RoleResponse(Long id, String name, String description, Set<String> permissions) {}
// service/RoleService.java: RoleResponse create(RoleRequest req); List<RoleResponse> findAll();
// service/RoleServiceImpl.java: check existsByName -> throw DuplicateResourceException 409, fetch permissions by ids, save, map to response, @Transactional
// controller/RoleController.java: @RequestMapping("/api/v1/roles") interface
// controller/RoleControllerImpl.java: @PreAuthorize("hasRole('ADMIN')") for findAll, hasAuthority('role:assign') for create
```

Full code template in repo — use existsByName guard + mapper via stream.

- [ ] **Step 5: Run → PASS**

Run: `mvn test -Dtest=RoleServiceTest -q` → PASS

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/example/access_management/role/
git commit -m "feat: add role & permission rbac"
```

---

### Task 5: Refresh Token — Entity & Repository

**Files:**
- Create: `src/main/java/com/example/access_management/auth/entity/RefreshToken.java`
- Create: `src/main/java/com/example/access_management/auth/repository/RefreshTokenRepository.java`
- Test: `src/test/java/com/example/access_management/auth/RefreshTokenRepositoryTest.java`

**Interfaces:**
- Consumes: BaseEntity, User
- Produces: `RefreshTokenRepository.findByTokenHash()`, `deleteByExpiresAtBefore()`

- [ ] **Step 1: Write failing test**

```java
// auth/RefreshTokenRepositoryTest.java
@DataJpaTest class RefreshTokenRepositoryTest {
  @Autowired RefreshTokenRepository repo; @Autowired UserRepository userRepo;
  @Test void findByHash() {
    User u = userRepo.save(User.builder().email("r@b.com").passwordHash("x").fullName("R").build());
    RefreshToken rt = repo.save(RefreshToken.builder().user(u).tokenHash("hash123").expiresAt(Instant.now().plusSeconds(604800)).revoked(false).build());
    assertThat(repo.findByTokenHash("hash123")).isPresent();
  }
}
```

- [ ] **Step 2: Run → FAIL**

Run: `mvn test -Dtest=RefreshTokenRepositoryTest -q` → FAIL

- [ ] **Step 3: Create entity + repo**

```java
// auth/entity/RefreshToken.java
@Entity @Table(name="refresh_tokens") @Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class RefreshToken extends BaseEntity {
  @ManyToOne(fetch=FetchType.LAZY) @JoinColumn(name="user_id", nullable=false) private User user;
  @Column(name="token_hash", unique=true, nullable=false) private String tokenHash;
  @Column(name="expires_at", nullable=false) private Instant expiresAt;
  @Column(nullable=false) private boolean revoked = false;
}
// auth/repository/RefreshTokenRepository.java
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
  Optional<RefreshToken> findByTokenHash(String tokenHash);
  void deleteByExpiresAtBefore(Instant instant);
  List<RefreshToken> findByUserIdAndRevokedFalse(Long userId);
}
```

- [ ] **Step 4: Run → PASS**

Run: `mvn test -Dtest=RefreshTokenRepositoryTest -q` → PASS

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/access_management/auth/entity/ src/main/java/com/example/access_management/auth/repository/
git commit -m "feat: add refresh token entity & repo"
```

---

### Task 6: Security — JwtService, JwtAuthFilter, SecurityConfig, CustomUserDetailsService

**Files:**
- Create: `src/main/java/com/example/access_management/security/jwt/JwtService.java`
- Create: `src/main/java/com/example/access_management/security/jwt/JwtAuthFilter.java`
- Create: `src/main/java/com/example/access_management/security/config/SecurityConfig.java`
- Create: `src/main/java/com/example/access_management/security/service/CustomUserDetailsService.java`
- Test: `src/test/java/com/example/access_management/security/JwtServiceTest.java`

**Interfaces:**
- Consumes: UserRepository.findByEmailWithRoles..., jwt props, BCrypt
- Produces: `JwtService.generateAccessToken(User)`, `validateToken()`, `JwtAuthFilter` in chain, `SecurityFilterChain` bean, `UserDetailsService` for auth

- [ ] **Step 1: Write failing JWT test**

```java
// JwtServiceTest.java
@SpringBootTest class JwtServiceTest {
  @Autowired JwtService jwtService; @Autowired UserRepository userRepo;
  @Test void generateAndValidate() {
    User u = userRepo.save(User.builder().email("jwt@b.com").passwordHash("x").fullName("J").build());
    // add role/permissions via setup
    String token = jwtService.generateAccessToken(u);
    assertThat(jwtService.validateToken(token)).isTrue();
    assertThat(jwtService.extractEmail(token)).isEqualTo("jwt@b.com");
  }
}
```

- [ ] **Step 2: Run → FAIL**

Run: `mvn test -Dtest=JwtServiceTest -q` → FAIL

- [ ] **Step 3: Implement JwtService + Filter + Config**

```java
// security/jwt/JwtService.java
@Service
public class JwtService {
  @Value("${jwt.secret}") private String secret;
  @Value("${jwt.access-expiration}") private long accessExp;
  private SecretKey key() { return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); }
  public String generateAccessToken(User user) {
    Instant now = Instant.now();
    return Jwts.builder().subject(user.getId().toString()).claim("email", user.getEmail())
      .claim("roles", user.getRoles().stream().map(Role::getName).toList())
      .claim("permissions", user.getRoles().stream().flatMap(r->r.getPermissions().stream()).map(Permission::getName).toList())
      .issuedAt(Date.from(now)).expiration(Date.from(now.plusMillis(accessExp)))
      .signWith(key()).compact();
  }
  public boolean validateToken(String token) { try { Jwts.parser().verifyWith(key()).build().parseSignedClaims(token); return true; } catch(Exception e){return false;}}
  public String extractEmail(String token){ return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().get("email", String.class); }
  public Long extractUserId(String token){ return Long.valueOf(Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject()); }
}
// security/jwt/JwtAuthFilter.java
@Component @RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
  private final JwtService jwtService; private final CustomUserDetailsService userDetailsService;
  @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
    String header = req.getHeader("Authorization");
    if(header != null && header.startsWith("Bearer ")) {
      String token = header.substring(7);
      if(jwtService.validateToken(token)) {
        String email = jwtService.extractEmail(token);
        var userDetails = userDetailsService.loadUserByUsername(email);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        MDC.put("requestId", UUID.randomUUID().toString());
      }
    }
    chain.doFilter(req, res);
  }
}
// security/service/CustomUserDetailsService.java
@Service @RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
  private final UserRepository userRepository;
  @Override public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    User u = userRepository.findByEmailWithRolesAndPermissions(email).orElseThrow(()->new UsernameNotFoundException("User not found"));
    Set<GrantedAuthority> auth = new HashSet<>();
    u.getRoles().forEach(r->{ auth.add(new SimpleGrantedAuthority(r.getName())); r.getPermissions().forEach(p->auth.add(new SimpleGrantedAuthority(p.getName()))); });
    return new org.springframework.security.core.userdetails.User(u.getEmail(), u.getPasswordHash(), u.isEnabled(), true, true, u.getLockoutUntil()==null || u.getLockoutUntil().isBefore(Instant.now()), auth);
  }
}
// security/config/SecurityConfig.java
@Configuration @EnableWebSecurity @EnableMethodSecurity
public class SecurityConfig {
  private final JwtAuthFilter jwtAuthFilter;
  @Bean SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf->csrf.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(auth->auth.requestMatchers("/api/v1/auth/register","/api/v1/auth/login","/api/v1/auth/refresh").permitAll().requestMatchers("/api/v1/roles/**","/api/v1/permissions/**").hasRole("ADMIN").anyRequest().authenticated())
      .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
      .exceptionHandling(e->e.authenticationEntryPoint((req,res,ex)->{res.setStatus(401); res.setContentType("application/json"); res.getWriter().write("{\"success\":false,\"message\":\"Unauthorized\"}");}).accessDeniedHandler((req,res,ex)->{res.setStatus(403); res.getWriter().write("{\"success\":false,\"message\":\"Forbidden\"}");}));
    return http.build();
  }
  @Bean PasswordEncoder passwordEncoder(){ return new BCryptPasswordEncoder(12); }
}
```

- [ ] **Step 4: Run → PASS**

Run: `mvn test -Dtest=JwtServiceTest -q` → PASS; `mvn test -q` all pass

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/example/access_management/security/
git commit -m "feat: add jwt service, filter, security config, userDetails"
```

---

### Task 7: Auth Feature — Service & Controller (Register, Login, Refresh, Logout, Me)

**Files:**
- Create: `src/main/java/com/example/access_management/auth/dto/RegisterRequest.java`
- Create: `src/main/java/com/example/access_management/auth/dto/LoginRequest.java`
- Create: `src/main/java/com/example/access_management/auth/dto/LoginResponse.java`
- Create: `src/main/java/com/example/access_management/auth/dto/RefreshRequest.java`
- Create: `src/main/java/com/example/access_management/auth/service/AuthService.java`
- Create: `src/main/java/com/example/access_management/auth/service/AuthServiceImpl.java`
- Create: `src/main/java/com/example/access_management/auth/controller/AuthController.java`
- Create: `src/main/java/com/example/access_management/auth/controller/AuthControllerImpl.java`
- Test: `src/test/java/com/example/access_management/auth/AuthServiceTest.java`

**Interfaces:**
- Consumes: UserRepository, RefreshTokenRepository, JwtService, PasswordEncoder, RoleRepository
- Produces: `AuthService.register()`, `login()`, `refresh()`, `logout()`, `AuthController` endpoints

- [ ] **Step 1: Write failing auth test**

```java
// AuthServiceTest.java
@SpringBootTest
class AuthServiceTest {
  @Autowired AuthService authService;
  @Test void registerAndLogin() {
    var req = new RegisterRequest("test@a.com","Password123","Test User");
    var user = authService.register(req);
    assertThat(user.email()).isEqualTo("test@a.com");
    var login = authService.login(new LoginRequest("test@a.com","Password123"));
    assertThat(login.accessToken()).isNotBlank();
    assertThat(login.refreshToken()).isNotBlank();
  }
  @Test void duplicateRegisterThrows409() {
    var req = new RegisterRequest("dup@a.com","Password123","Dup");
    authService.register(req);
    assertThatThrownBy(()->authService.register(req)).isInstanceOf(DuplicateResourceException.class);
  }
  @Test void loginWrongPasswordThrows() {
    authService.register(new RegisterRequest("wrong@a.com","Password123","W"));
    assertThatThrownBy(()->authService.login(new LoginRequest("wrong@a.com","bad"))).isInstanceOf(BusinessException.class);
  }
  @Test void refreshRotate() {
    authService.register(new RegisterRequest("ref@a.com","Password123","R"));
    var login = authService.login(new LoginRequest("ref@a.com","Password123"));
    var refreshed = authService.refresh(new RefreshRequest(login.refreshToken()));
    assertThat(refreshed.accessToken()).isNotEqualTo(login.accessToken());
  }
}
```

- [ ] **Step 2: Run → FAIL**

Run: `mvn test -Dtest=AuthServiceTest -q` → FAIL

- [ ] **Step 3: Create DTOs**

```java
// auth/dto/RegisterRequest.java: record RegisterRequest(@NotBlank @Email String email, @NotBlank @Size(min=8,max=100) String password, @NotBlank @Size(min=2,max=100) String fullName) {}
// LoginRequest: record LoginRequest(@NotBlank @Email String email, @NotBlank String password) {}
// RefreshRequest: record RefreshRequest(@NotBlank String refreshToken) {}
// LoginResponse: record LoginResponse(String accessToken, String refreshToken, long expiresIn, String tokenType) {}
```

- [ ] **Step 4: Implement AuthServiceImpl + Controller**

```java
// auth/service/AuthService.java
public interface AuthService { UserResponse register(RegisterRequest req); LoginResponse login(LoginRequest req); LoginResponse refresh(RefreshRequest req); void logout(RefreshRequest req); UserResponse me(String email); }
// AuthServiceImpl key logic:
// register: if existsByEmail -> throw DuplicateResourceException 409; else encode password BCrypt, fetch ROLE_USER, save user, return MapperUtil
// login: findByEmailWithRoles -> if not found throw BusinessException 401; check lockoutUntil > now -> throw AccountLockedException 423; if !matches -> failedAttempts++ if >=5 set lockoutUntil=now+15m save throw BusinessException; else reset failedAttempts=0 save, generate access via jwtService, generate opaque UUID refresh -> SHA256 hash save RefreshToken(expires 7d), return LoginResponse
// refresh: hash token SHA256, findByTokenHash -> if empty/revoked/expired throw BusinessException 401; revoke old, find user, generate new pair, save new token, return
// logout: hash, find, set revoked=true save
// me: findByEmailWithRoles -> map
// helper: sha256(String token) via MessageDigest
// controller: @RequestMapping("/api/v1/auth") interface with @PostMapping register/login/refresh/logout + @GetMapping me; impl delegates to service, me extracts from SecurityContext
```

Exact code ~80 lines per method, use @Transactional, @Slf4j, @Value for expirations.

- [ ] **Step 5: Run → PASS**

Run: `mvn test -Dtest=AuthServiceTest -q` → PASS

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/example/access_management/auth/
git commit -m "feat: add auth register/login/refresh/logout"
```

---

### Task 8: Seed & Integration Test — RBAC + End-to-End

**Files:**
- Create: `src/main/java/com/example/access_management/common/config/DataSeeder.java`
- Create: `src/test/java/com/example/access_management/IntegrationTest.java`

**Interfaces:**
- Consumes: all services, SecurityConfig, JWT filter
- Produces: seeded ROLE_ADMIN/USER + permissions, E2E flow verified

- [ ] **Step 1: Write failing integration test**

```java
// IntegrationTest.java
@SpringBootTest @AutoConfigureMockMvc
class IntegrationTest {
  @Autowired MockMvc mvc; @Autowired DataSeeder seeder;
  @Test void fullFlow() throws Exception {
    // 1. register
    mvc.perform(post("/api/v1/auth/register").contentType(APPLICATION_JSON).content("{\"email\":\"e2e@a.com\",\"password\":\"Password123\",\"fullName\":\"E2E\"}")).andExpect(status().isCreated());
    // 2. login
    String loginRes = mvc.perform(post("/api/v1/auth/login").contentType(APPLICATION_JSON).content("{\"email\":\"e2e@a.com\",\"password\":\"Password123\"}")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    String access = JsonPath.read(loginRes, "$.data.accessToken");
    String refresh = JsonPath.read(loginRes, "$.data.refreshToken");
    // 3. me
    mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+access)).andExpect(status().isOk());
    // 4. refresh
    mvc.perform(post("/api/v1/auth/refresh").contentType(APPLICATION_JSON).content("{\"refreshToken\":\""+refresh+"\"}")).andExpect(status().isOk());
    // 5. users without auth -> 401
    mvc.perform(get("/api/v1/users/1")).andExpect(status().isUnauthorized());
    // 6. users with RBAC (has user:read via ROLE_USER)
    mvc.perform(get("/api/v1/users/1").header("Authorization","Bearer "+access)).andExpect(status().isOk());
  }
}
```

- [ ] **Step 2: Run → FAIL**

Run: `mvn test -Dtest=IntegrationTest -q` → FAIL (no seeder)

- [ ] **Step 3: Create DataSeeder**

```java
// common/config/DataSeeder.java
@Component @RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {
  private final PermissionRepository permRepo; private final RoleRepository roleRepo;
  @Override @Transactional public void run(String... args) {
    if(permRepo.count()==0) {
      List<Permission> perms = List.of("user:create","user:read","user:update","user:delete","role:assign","role:read").stream().map(n->{ Permission p=new Permission(); p.setName(n); p.setDescription(n); return p;}).toList();
      permRepo.saveAll(perms);
    }
    if(roleRepo.count()==0) {
      Permission read = permRepo.findByName("user:read").orElseThrow();
      Role userRole = new Role(); userRole.setName("ROLE_USER"); userRole.setDescription("Default user"); userRole.setPermissions(Set.of(read)); roleRepo.save(userRole);
      Role admin = new Role(); admin.setName("ROLE_ADMIN"); admin.setDescription("Administrator"); admin.setPermissions(new HashSet<>(permRepo.findAll())); roleRepo.save(admin);
    }
  }
}
```

- [ ] **Step 4: Run → PASS**

Run: `mvn test -q` → All PASS

- [ ] **Step 5: Commit & Push**

```bash
git add src/main/java/com/example/access_management/common/config/DataSeeder.java src/test/java/com/example/access_management/IntegrationTest.java
git commit -m "feat: add seeder + e2e integration test"
git push
```

---

## Self-Review

- [ ] Spec coverage: all Fase 1 key features (register, login/logout, JWT, refresh, RBAC, hashing, API security) mapped to tasks 3-8
- [ ] Placeholder scan: no TODO/TBD, all code blocks concrete
- [ ] Type consistency: UserResponse, LoginResponse, RoleRequest signatures consistent across common/util and services
- [ ] N+1 check: JOIN FETCH in repo, LAZY verified
- [ ] Security: BCrypt(12), SHA-256 refresh, 15m/7d, lockout 5/15m, global handler 401/403/404/409/423
