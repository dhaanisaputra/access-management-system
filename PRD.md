# PRD — Identity & Access Management Platform (Auth0/Okta Mini)

> **Goal:** Build your own authentication & authorization service that other applications can use. Simplified Auth0/Okta-style identity service.
> **Stack:** Java 25 + Spring Boot 4.1.1 + Spring Security + PostgreSQL + Redis (Fase 2+)
> **DB:** `access_management_platform` (PostgreSQL) — HikariCP
> **Status:** Fase 1 → Fase 4 bertahap (ponytail: ship slice terkecil yang jalan)

---

## 1. What You'll Learn (coverage)

| Materi | Dicapai di |
| :--- | :--- |
| Spring Security | Fase 1 (filter chain, method security) |
| JWT | Fase 1 (access 15m, opaque refresh 7d rotate) |
| OAuth2 | Fase 3 (Google/GitHub login) |
| RBAC | Fase 1 (Role + Permission) |
| Security best practices | Semua fase (BCrypt, hash token, lockout, validation) |
| Session management | Fase 2 (Redis + user_sessions) |
| Password hashing | Fase 1 (BCrypt 12) |
| API security | Semua fase (stateless, CSRF off, CORS, 401/403 handler) |

**Resume Value:** ★★★★★ — Security reusable untuk hampir semua backend.

---

## 2. Key Features — Roadmap Fase

### Fase 1 — MVP Inti (Sekarang)
- [ ] User registration
- [ ] Login / logout
- [ ] JWT authentication (access 15m)
- [ ] Refresh tokens (opaque DB, rotate, R1 tanpa Redis)
- [ ] Role-based access control (Role + Permission)
- [ ] Password hashing (BCrypt)
- [ ] API security (filter, @PreAuthorize)

### Fase 2 — Security Hardening (butuh Redis)
- [ ] Email verification (token 24j, table `email_verification_tokens`)
- [ ] Password reset (token 15-60m, table `password_reset_tokens`)
- [ ] Session management (Redis + `user_sessions`, blacklist access JWT)
- [ ] Account lockout (failedAttempts >=5 → lock 15m, `login_attempts` audit)

### Fase 3 — Federated Identity
- [ ] OAuth2 login (Google/GitHub, `oauth_accounts`, `spring-boot-starter-oauth2-client`)

### Fase 4 — AI Features (opsional, pondasi sudah ada)
- [ ] Suspicious Login Detection (IP/anomaly dari `login_attempts`)
- [ ] Risk-Based Authentication
- [ ] Behavior Anomaly Detection
- [ ] AI Security Assistant
- [ ] Access Risk Analysis

---

## 3. Architecture & Folder Structure (Senior, DRY)

**Pattern:** Modular Monolith, **feature-based** level 1, **layer-based** level 2 per fitur.
Aturan: `Controller (interface) -> ControllerImpl -> Service (interface) -> ServiceImpl (logic bisnis)`. Logic **hanya** di `*ServiceImpl`.

```
com.example.access_management
├─ auth/
│   ├─ controller/ {AuthController.java (interface), AuthControllerImpl.java}
│   ├─ service/ {AuthService.java, AuthServiceImpl.java}
│   ├─ dto/ {RegisterRequest, LoginRequest, LoginResponse, RefreshRequest} (record + @Valid)
│   ├─ entity/ {RefreshToken.java}
│   └─ repository/ {RefreshTokenRepository.java}
├─ user/
│   ├─ controller/ {UserController.java, UserControllerImpl.java}
│   ├─ service/ {UserService.java, UserServiceImpl.java}
│   ├─ repository/ {UserRepository.java}
│   ├─ entity/ {User.java}
│   └─ dto/ {UserResponse, UserCreateRequest}
├─ role/
│   ├─ controller/ {RoleController.java, RoleControllerImpl.java}
│   ├─ service/ {RoleService.java, RoleServiceImpl.java}
│   ├─ repository/ {RoleRepository.java, PermissionRepository.java}
│   ├─ entity/ {Role.java, Permission.java}
│   └─ dto/ {RoleRequest, RoleResponse}
├─ security/
│   ├─ config/ {SecurityConfig.java}
│   ├─ jwt/ {JwtService.java, JwtAuthFilter.java}
│   └─ service/ {CustomUserDetailsService.java}
└─ common/
    ├─ entity/ {BaseEntity.java (@MappedSuperclass: id, createdAt, updatedAt)}
    ├─ dto/ {ApiResponse.java (record<T> success, message, data, timestamp)}
    ├─ exception/ {GlobalExceptionHandler.java, ResourceNotFoundException, DuplicateResourceException, BusinessException, AccountLockedException}
    ├─ util/ {MapperUtil.java (manual, tanpa MapStruct)}
    └─ logging/ {LoggingAspect.java (@Aspect, log method+time, mask password/token)}
```

**Dependencies (pom):** `spring-boot-starter-webmvc`, `security`, `data-jpa`, `validation` (tambahan), `postgresql`, `jjwt` (io.jsonwebtoken), `lombok`, `redis` (Fase 2).

---

## 4. Data Model — 8 Tabel (Final, cover semua Key Features)

**ERD:** `users 1--* user_roles *--1 roles 1--* role_permissions *--1 permissions` + `users 1--* {refresh_tokens, email_verification_tokens, password_reset_tokens, oauth_accounts, user_sessions, login_attempts}`

### 4.1 users
`id BIGSERIAL PK, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, full_name VARCHAR(100) NOT NULL, enabled BOOLEAN DEFAULT true, email_verified BOOLEAN DEFAULT false, failed_attempts INT DEFAULT 0, lockout_until TIMESTAMP NULL, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL` — INDEX UNIQUE(email)

### 4.2 roles
`id BIGSERIAL PK, name VARCHAR(50) UNIQUE NOT NULL (ROLE_ADMIN, ROLE_USER), description VARCHAR(255), created_at, updated_at` — seed: ROLE_ADMIN, ROLE_USER

### 4.3 permissions
`id BIGSERIAL PK, name VARCHAR(100) UNIQUE NOT NULL (user:create, user:read, user:update, user:delete, role:assign, role:read), description, created_at` — seed 6 permission awal

### 4.4 user_roles (join)
`user_id FK users.id CASCADE, role_id FK roles.id, PK(user_id, role_id)` — INDEX(user_id), INDEX(role_id)

### 4.5 role_permissions (join)
`role_id FK, permission_id FK, PK(role_id, permission_id)`

### 4.6 refresh_tokens (R1 opaque)
`id BIGSERIAL PK, user_id FK CASCADE, token_hash VARCHAR(255) UNIQUE NOT NULL (SHA-256 dari UUID), expires_at TIMESTAMP NOT NULL (now+7d), revoked BOOLEAN DEFAULT false, created_at` — INDEX(token_hash), INDEX(user_id, revoked), INDEX(expires_at) + @Scheduled cleanup

### 4.7 email_verification_tokens (Fase 2)
`id, user_id FK, token_hash UNIQUE, expires_at (24j), used BOOLEAN DEFAULT false, created_at`

### 4.8 password_reset_tokens (Fase 2)
`id, user_id FK, token_hash UNIQUE, expires_at (15-60m), used BOOLEAN DEFAULT false, created_at`

### 4.9 oauth_accounts (Fase 3)
`id, user_id FK, provider VARCHAR(20) (google/github), provider_user_id VARCHAR(255) UNIQUE, email VARCHAR(255), created_at` — UNIQUE(provider, provider_user_id)

### 4.10 user_sessions + login_attempts (Fase 2, pondasi AI)
`sessions: id, user_id FK, ip_address, user_agent, last_active, is_active` — untuk Redis sync
`login_attempts: id, user_id/email, ip, success BOOLEAN, attempted_at TIMESTAMP` — INDEX(email, attempted_at), insert async (@Async)

**Anti N+1:**
- Semua `@ManyToMany(fetch=LAZY)`, tidak ada EAGER.
- `UserRepository.existsByEmail(email)` untuk cek duplicate (tanpa load entity).
- `findByEmailWithRolesAndPermissions()` via `@Query JOIN FETCH u.roles r JOIN FETCH r.permissions` — 1 query untuk CustomUserDetailsService.
- `findByTokenHash()` pakai index, `findByIdWithRoles()` pakai @EntityGraph.

**Fase aktif:**
- Fase 1: users, roles, permissions, user_roles, role_permissions, refresh_tokens, login_attempts
- Fase 2: + email_verification_tokens, password_reset_tokens, user_sessions (butuh Redis)
- Fase 3: + oauth_accounts

---

## 5. API Contract (Fase 1 — prefix /api/v1)

| Method | Endpoint | Auth | RBAC | Request | Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| POST | /api/v1/auth/register | public | - | RegisterRequest{email, password, fullName} | 201 ApiResponse<UserResponse> |
| POST | /api/v1/auth/login | public | - | LoginRequest{email, password} | 200 LoginResponse{accessToken, refreshToken, expiresIn=900, tokenType="Bearer"} |
| POST | /api/v1/auth/refresh | public | - | RefreshRequest{refreshToken} | 200 LoginResponse{newAccessToken, newRefreshToken} (rotate, revoke old) |
| POST | /api/v1/auth/logout | Bearer | authenticated | RefreshRequest{refreshToken} | 204 (revoke refresh) |
| GET | /api/v1/auth/me | Bearer | authenticated | - | 200 ApiResponse<UserResponse> |
| GET | /api/v1/users | Bearer | hasAuthority('user:read') | Pageable | 200 Page<ApiResponse<UserResponse>> |
| GET | /api/v1/users/{id} | Bearer | hasAuthority('user:read') | - | 200 ApiResponse<UserResponse> |
| PATCH | /api/v1/users/{id}/roles | Bearer | hasAuthority('role:assign') | {roleIds} | 200 ApiResponse<UserResponse> |
| GET | /api/v1/roles | Bearer | hasRole('ADMIN') | - | 200 ApiResponse<List<RoleResponse>> |
| POST | /api/v1/roles | Bearer | hasAuthority('role:assign') | RoleRequest{name, permissionIds} | 201 ApiResponse<RoleResponse> |
| GET | /api/v1/permissions | Bearer | hasRole('ADMIN') | - | 200 ApiResponse<List<PermissionResponse>> |

Reserved Fase 2/3: `POST /auth/verify-email`, `POST /auth/forgot-password`, `POST /auth/reset-password`, `GET /oauth2/authorization/{provider}`

**Response wrapper:**
```java
public record ApiResponse<T>(boolean success, String message, T data, Instant timestamp) {
  public static <T> ApiResponse<T> ok(T data) { ... }
  public static <T> ApiResponse<T> created(T data) { ... }
}
```

---

## 6. Security Flow — JWT 15m + Silent Refresh (Opsi A)

```
[Client] --1 POST /auth/login--> AuthServiceImpl: cek lockout, BCrypt.matches, reset/increment failedAttempts, log login_attempts
  <- {access 15m (JWT HS256: sub=userId, email, roles, permissions, iat, exp), refresh 7d (UUID plain ke client, hash SHA-256 simpan DB)}

[Client] --2 GET /users + Bearer access--> JwtAuthFilter (OncePerRequestFilter): extract, JwtService.validate(signature+exp), load UserDetails via CustomUserDetailsService (findByEmailWithRoles 1 query), set SecurityContext -> SecurityConfig authorize -> @PreAuthorize

[Client] --expired 401--> Frontend interceptor: POST /auth/refresh {refreshToken} -> hash, findByTokenHash, cek revoked/exp, revoke old, issue new pair (rotate) -> retry request awal (user tidak re-login)

[Client] --logout--> POST /auth/logout {refreshToken} -> revoke (access tetap valid max 15m, Fase 2 blacklist Redis)
```

**SecurityConfig:**
`csrf.disable(), sessionCreationPolicy(STATELESS), authorize: permitAll(/auth/register, /auth/login, /auth/refresh), /roles/** hasRole ADMIN, anyRequest authenticated, addFilterBefore(jwtAuthFilter), exceptionHandling: AuthenticationEntryPoint 401, AccessDeniedHandler 403, BCryptPasswordEncoder(12), @EnableMethodSecurity`

**RBAC:** `GrantedAuthority` dari `role.name` + `permission.name`; `@PreAuthorize("hasAuthority('user:read')")` di controller.

**Account Lockout (AuthServiceImpl):** `if (!matches) { failedAttempts++; if >=5 lockoutUntil=now+15m; save }` — async insert login_attempts.

**Config:** `jwt.secret` (env 256-bit), `jwt.access-expiration=15m`, `jwt.refresh-expiration=7d`, `app.lockout.threshold=5` — ponytail: 15m default, naikkan ke 30m jika UX komplain tanpa ubah code.

---

## 7. Validation & Error Handling (Global)

**DTO validation (fail fast di controller):**
`RegisterRequest: @NotBlank @Email email, @NotBlank @Size(8-100) password, @NotBlank @Size(2-100) fullName` + `@Valid` di controller -> `MethodArgumentNotValidException` -> 400 `ApiResponse{errors:[{field,msg}]}`

**Business validation (ServiceImpl throw):**
| Case | Check | Exception | HTTP |
| :--- | :--- | :--- | :--- |
| Duplicate email/role | existsByEmail / existsByName | DuplicateResourceException | 409 |
| Not found (user/role/permission/token) | findById/hash orElseThrow | ResourceNotFoundException | 404 |
| Invalid credentials | email not found / password mismatch | BusinessException | 401 |
| Account locked | lockoutUntil > now | AccountLockedException | 423 |
| Refresh invalid | revoked / expired / not found | BusinessException | 401 |
| RBAC fail | @PreAuthorize | AccessDeniedException | 403 |
| JWT invalid | filter validate | AuthenticationEntryPoint | 401 |
| Unexpected | catch all | Exception | 500 (log.error, hide stack) |

DB guard: `UNIQUE` constraint -> `DataIntegrityViolationException` -> 409 (anti race).
Semua via `GlobalExceptionHandler (@RestControllerAdvice)` format `ApiResponse{success:false, message, timestamp}`.

---

## 8. Coding Standards — Senior

- **DRY:** BaseEntity, ApiResponse, MapperUtil (manual, tanpa MapStruct), JwtService, GlobalHandler — 1 tempat.
- **Logging:** @Slf4j di ServiceImpl (debug flow, info auth event, warn lockout, error exception); LoggingAspect @Around ServiceImpl log method+args(masked)+timeMs; MDC requestId di JwtAuthFilter.
- **Query efisien:** LAZY, existsBy, JOIN FETCH / @EntityGraph, Pageable size=20, index di email/token_hash.
- **Transaction:** @Transactional di ServiceImpl, readOnly untuk get.
- **Hashing:** BCrypt(12) password, SHA-256 refresh/verification token (jangan simpan plain).
- **Validation:** record DTO + Jakarta Validation, BusinessException untuk domain.
- **Security:** HS256, secret env, CORS config, tidak expose stack trace.

---

## 9. Definition of Done — Fase 1

- [ ] Register/Login/Refresh/Logout jalan, JWT 15m + refresh rotate 7d
- [ ] RBAC: seed ROLE_ADMIN/USER + 6 permission, @PreAuthorize enforce
- [ ] Global Handler + ApiResponse konsisten untuk semua error
- [ ] Anti N+1 verified (1 query untuk load user+roles+permissions)
- [ ] LoggingAspect + BCrypt + token hash
- [ ] Validasi duplicate/not found/lockout ter-handle 409/404/423
- [ ] Postman / curl demo tanpa re-login tiap 15m (silent refresh)

---

## 10. Next Steps

1. Init git + `docs/` sesuai PRD ini
2. Tambah `spring-boot-starter-validation`, `jjwt` ke pom
3. Implement Fase 1 vertical slice: BaseEntity -> User -> Auth -> Security -> Role
4. Fase 2: tambah Redis, email (SMTP mock), session blacklist
5. Fase 3: OAuth2 client
6. Fase 4: AI anomaly (pakai data login_attempts/user_sessions)

> **Ponytail:** Fase 1 tanpa Redis, tanpa Flyway (ddl-auto=update), tanpa MapStruct — tambah hanya jika Fase 2+ butuh. Singkat, jalan, siap di-extend.
