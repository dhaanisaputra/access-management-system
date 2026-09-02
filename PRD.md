# PRD — Identity & Access Management Platform (Auth0/Okta Mini)

> **Goal:** Build your own authentication & authorization service that other applications can use. Simplified Auth0/Okta-style identity service.
> **Stack:** Java 25 + Spring Boot 4.1.1 + Spring Security + PostgreSQL + Redis + OAuth2 + SpringDoc OpenAPI
> **DB:** `access_management_platform` (PostgreSQL) — HikariCP, Redis 7 (6379)
> **Status:** Fase 1-4B DONE (56 tests, BUILD SUCCESS) — ponytail: ship slice terkecil yang jalan, now intl standard + rich domain OOP

---

## 1. What You'll Learn (coverage) — DONE

| Materi | Dicapai di | Evidence |
| :--- | :--- | :--- |
| Spring Security | Fase 1 (filter chain, method security, `SecurityConfig.java:21`) | `JwtAuthFilter`, `@PreAuthorize`, `CustomUserDetailsService` |
| JWT | Fase 1 (access 15m + jti, opaque refresh 7d rotate, SHA-256) | `JwtService.java:30` HS256, `RefreshToken` |
| OAuth2 | Fase 3 (Google, `spring-boot-starter-oauth2-client`) | `OAuthAccount`, `CustomOAuth2SuccessHandler`, `/oauth2/authorization/google` |
| RBAC | Fase 1 (Role+Permission, `ROLE_*`, `hasAuthority`) | `Role`, `Permission`, seed 6 perms |
| Security best practices | Semua fase (BCrypt12, SHA-256, lockout, validation, blacklist) | `GlobalExceptionHandler`, `ApiResponse` |
| Session management | Fase 2 (Redis blacklist jti + `UserSession` + `LoginAttempt` async) | `RedisBlacklistService`, `TokenCleanupScheduler` |
| Password hashing | Fase 1 (BCrypt12) | `PasswordEncoderConfig` |
| API security | Semua fase (stateless CSRF off, 401/403/404/409/423, Swagger bearerAuth) | `OpenApiConfig`, `SecurityConfig` |

**Resume Value:** ★★★★★ — Security reusable untuk hampir semua backend. Swagger di `/swagger-ui.html`.

---

## 2. Key Features — Roadmap Fase (update status)

### Fase 1 — MVP Inti ✅ DONE (Fase 1: 18 tests)
- [x] User registration — `User.create()`, `existsByEmail` 409, record DTO @Valid
- [x] Login / logout — `AuthService.login` + `logout` (revoke refresh + blacklist jti)
- [x] JWT authentication (access 15m + jti) — `JwtService.generateAccessToken` HS256
- [x] Refresh tokens (opaque DB, rotate, SHA-256, 7d) — `RefreshTokenRepository.findByTokenHash`
- [x] Role-based access control (Role + Permission, `ROLE_ADMIN/USER` + 6 perms) — `@PreAuthorize`
- [x] Password hashing (BCrypt12)
- [x] API security (filter chain, `@EnableMethodSecurity`) — intl standard

### Fase 2 — Security Hardening ✅ DONE (35 tests)
- [x] Email verification (24h `EmailVerificationToken`, `POST /verify-email`, `resend-verification`, mock `EmailService` log)
- [x] Password reset (60m `PasswordResetToken`, `POST /forgot-password`, `POST /reset-password`, revoke refresh on reset)
- [x] Session management (Redis `RedisBlacklistService` blacklist jti TTL=remaining, `UserSession` ip/userAgent/country, `JwtAuthFilter` blacklist check)
- [x] Account lockout (rich domain `User.isLocked()/recordFailedAttempt()/resetLockout()` threshold 5 lock 15m, `LoginAttempt` async via `@EnableAsync`)

### Fase 3 — Federated Identity ✅ DONE (45 tests)
- [x] OAuth2 login (Google, `oauth_accounts` unique `provider+providerUserId`, `OAuthAccountService.processOAuthUser()` link by email or create `User.create()` + `verifyEmail()`, `CustomOAuth2SuccessHandler` JSON `LoginResponse`, `SecurityConfig.oauth2Login`)

### Fase 4B — AI Features (rule-based) ✅ DONE (56 tests)
- [x] Suspicious Login Detection — `RiskScoringService` new IP +40, new device +30
- [x] Risk-Based Authentication — score 0-100 → LOW<40 MEDIUM 40-70 HIGH>70, outside-hours +10, fails>3 +20, `LoginResponse.riskScore/riskLevel/suspicious`
- [x] Access Risk Analysis — `GET /api/v1/admin/risk-analysis` `@PreAuthorize("hasRole('ADMIN')")` aggregate high/medium/low + top 10 risky users + risky perms (`role:assign` etc via `findByPermissionName`)
- [ ] Behavior Anomaly Detection — *skipped, add when ML needed*
- [ ] AI Security Assistant — *skipped, add OpenRouter LLM when needed*

**Next Fase 4 full:** Anomaly ML (isolation forest) + Assistant LLM RAG.

---

## 3. Architecture & Folder Structure (Intl Standard, Rich Domain)

**Pattern:** Modular Monolith, feature-based lvl1, layer lvl2. **Intl standard:** single `@RestController` + `@Service` (no interface with one impl), service returns DTO, controller returns `ResponseEntity<ApiResponse<T>>`. Rich domain OOP: behavior di entity, bukan di service.

```
com.example.access_management
├─ auth/
│   ├─ controller/AuthController.java (@RestController @RequestMapping("/api/v1/auth") -> ResponseEntity<ApiResponse>)
│   ├─ service/AuthService.java (@Service, business, @Transactional)
│   ├─ dto/ {RegisterRequest, LoginRequest, LoginResponse (with risk fields), RefreshRequest, VerifyEmailRequest, Forgot/Reset} (record + @Valid)
│   ├─ entity/ {RefreshToken, EmailVerificationToken, PasswordResetToken, LoginAttempt, OAuthAccount, UserSession}
│   └─ repository/ {RefreshTokenRepository, EmailVerificationTokenRepository, PasswordResetTokenRepository, LoginAttemptRepository, OAuthAccountRepository, UserSessionRepository}
├─ user/
│   ├─ controller/UserController.java
│   ├─ service/UserService.java (returns UserResponse DTO)
│   ├─ repository/UserRepository.java (existsByEmail, findByEmailWithRolesAndPermissions JOIN FETCH)
│   ├─ entity/User.java (rich: User.create(), isLocked(), recordFailedAttempt(), resetLockout(), assignRole())
│   └─ dto/UserResponse.java (record)
├─ role/
│   ├─ controller/RoleController.java (@PreAuthorize)
│   ├─ service/RoleService.java
│   ├─ repository/ {RoleRepository, PermissionRepository}
│   ├─ entity/ {Role (addPermission/hasPermission), Permission}
│   └─ dto/ {RoleRequest, RoleResponse} (record)
├─ security/
│   ├─ config/ {SecurityConfig, RedisConfig, OpenApiConfig, PasswordEncoderConfig, AsyncConfig (@EnableAsync @EnableScheduling)}
│   ├─ jwt/ {JwtService (HS256, jti, extractJti/getExpiration), JwtAuthFilter (blacklist check, MDC)}
│   └─ service/ {CustomUserDetailsService, CustomOAuth2SuccessHandler, RedisBlacklistService}
├─ ai/  (Fase 4B)
│   ├─ service/ {RiskScoringService (geoip2 mock + ua-parser), AccessRiskAnalysisService}
│   ├─ controller/RiskAnalysisController.java (GET /admin/risk-analysis)
│   └─ dto/RiskAnalysisResponse.java
└─ common/
    ├─ entity/BaseEntity.java (@MappedSuperclass, protected setId, @PrePersist/@PreUpdate)
    ├─ dto/ApiResponse.java (record<T> success, message, data, timestamp, ok/created)
    ├─ exception/ {GlobalExceptionHandler (@RestControllerAdvice 404/409/423/400/401/403/500 + AuthorizationDeniedException), ResourceNotFound etc}
    ├─ service/EmailService.java (mock log, lastVerificationToken for tests)
    ├─ util/MapperUtil.java
    ├─ logging/LoggingAspect.java (AOP @Around *Service)
    └─ scheduler/TokenCleanupScheduler.java (@Scheduled fixedDelay 86400000, @Modifying deleteByExpiresAtBefore)
```

**Dependencies (pom):** `webmvc, security, oauth2-client, data-jpa, validation, data-redis, postgresql, jjwt 0.12.5, geoip2 2.17.0, uap-java 1.5.4, springdoc 2.8.5, lombok, h2 test`.

---

## 4. Data Model — 10+ Tabel (cover semua Key Features)

**ERD:** `users 1--* user_roles *--1 roles 1--* role_permissions *--1 permissions` + `users 1--* {refresh_tokens, email_verification_tokens, password_reset_tokens, oauth_accounts, user_sessions, login_attempts}`

### 4.1 users
`id BIGSERIAL PK, email UNIQUE, password_hash, full_name, enabled, email_verified, failed_attempts, lockout_until, created_at, updated_at` — rich methods `isLocked(), recordFailedAttempt(), resetLockout()`.

### 4.2 roles / 4.3 permissions / 4.4 user_roles / 4.5 role_permissions
As before; `Role.addPermission/hasPermission()`.

### 4.6 refresh_tokens
`id, user_id FK CASCADE, token_hash UNIQUE SHA-256, expires_at (7d), revoked, created_at` — INDEX(token_hash), @Scheduled cleanup.

### 4.7 email_verification_tokens
`id, user_id FK, token_hash UNIQUE, expires_at (24h), used, created_at` — `markUsed()/isExpired()`.

### 4.8 password_reset_tokens
`id, user_id FK, token_hash UNIQUE, expires_at (60m), used, created_at`.

### 4.9 oauth_accounts
`id, user_id FK, provider (google), provider_user_id UNIQUE, email, created_at` — UNIQUE(provider, providerUserId).

### 4.10 user_sessions
`id, user_id FK, ip_address, user_agent, country, city, device, os, browser, last_active, is_active` — feed AI risk.

### 4.11 login_attempts
`id, email, ip, success, attempted_at` — async `@Async`, INDEX(email, attempted_at).

**Anti N+1:** `@ManyToMany LAZY`, `existsByEmail`, `findByEmailWithRolesAndPermissions()` `LEFT JOIN FETCH u.roles r LEFT JOIN FETCH r.permissions`, `findByTokenHash` indexed.

**Fase aktif:** 1: users/roles/permissions/refresh/login_attempts → 2: +verify/reset/sessions → 3: +oauth → 4B: +risk scoring.

---

## 5. API Contract (prefix `/api/v1`, Swagger bearerAuth)

| Method | Endpoint | Auth | RBAC | Request | Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| POST | /auth/register | public | - | RegisterRequest{email, password, fullName} @Valid | 201 ApiResponse<UserResponse> (+ creates 24h verify token) |
| POST | /auth/login | public | - | LoginRequest{email, password} | 200 LoginResponse{accessToken (15m+jti), refreshToken, expiresIn, riskScore, riskLevel, suspicious, riskReasons} |
| POST | /auth/refresh | public | - | RefreshRequest{refreshToken} | 200 LoginResponse (rotate, revoke old) |
| POST | /auth/logout | Bearer | auth | RefreshRequest + `Authorization: Bearer <access>` | 200 (revoke refresh + blacklist jti TTL) |
| GET | /auth/me | Bearer | auth | - | 200 ApiResponse<UserResponse> |
| POST | /auth/verify-email | public | - | `?token=` or VerifyEmailRequest | 200 ApiResponse<UserResponse> (verifyEmail true) |
| POST | /auth/resend-verification | public | - | {email} | 200 |
| POST | /auth/forgot-password | public | - | {email} | 200 (creates 60m token, mock email) |
| POST | /auth/reset-password | public | - | {token, newPassword} @Size8 | 200 (changePasswordHash, revoke refresh) |
| GET | /oauth2/authorization/google | public | - | - | 302 redirect Google, callback `GET /login/oauth2/code/google` -> JSON LoginResponse |
| GET | /users/{id} | Bearer | `hasAuthority('user:read')` | - | 200 ApiResponse<UserResponse> |
| POST | /roles | Bearer | `hasAuthority('role:assign')` | RoleRequest{name, permissionIds} @Valid | 201 ApiResponse<RoleResponse> |
| GET | /roles | Bearer | `hasRole('ADMIN')` | - | 200 ApiResponse<List<RoleResponse>> |
| GET | /admin/risk-analysis | Bearer | `hasRole('ADMIN')` | - | 200 ApiResponse<RiskAnalysisResponse>{total, high/medium/low, topRiskyUsers[10], riskyPermissions}> |

Swagger: `/swagger-ui.html`, `/api-docs` (permitAll).

**Response wrapper:** `record ApiResponse<T>(boolean success, String message, T data, Instant timestamp) { ok(), created() }`.

---

## 6. Security Flow — JWT 15m + Silent Refresh + Risk (current)

```
[Client] --POST /login {email,pass}--> AuthService: User.isLocked()?, BCrypt.matches, User.recordFailedAttempt()/resetLockout(), RiskScoringService.calculateRisk(ip, ua) -> LoginAttempt async + UserSession, JwtService.generateAccessToken (HS256, sub=id, jti=UUID, email, roles, perms, iat, exp 15m) + UUID refresh SHA-256 DB 7d -> LoginResponse{..., risk*}
[Client] --GET /users + Bearer--> JwtAuthFilter: extract Bearer, JwtService.validate, extractJti -> RedisBlacklist.isBlacklisted? 401 "Token revoked" : load UserDetails JOIN FETCH 1 query -> SecurityContext -> @PreAuthorize
[Client] --expired 401--> POST /refresh {refreshToken} -> hash, find, check revoked/exp, revoke old, new pair -> retry
[Client] --logout--> POST /logout {refreshToken} + Bearer access -> blacklist jti TTL=remaining + revoke refresh
[OAuth] --GET /oauth2/authorization/google--> CustomOAuth2SuccessHandler.processOAuthUser (find/link/create User.create + verifyEmail) -> JWT + refresh JSON
```

**SecurityConfig:** `csrf.disable(), stateless, permitAll(/auth/register,login,refresh,verify-email,resend,forgot,reset, /oauth2/**, /login/oauth2/**, /swagger-ui/**, /api-docs/**), hasRole ADMIN, addFilterBefore(jwtAuthFilter), 401/403 JSON, BCrypt(12), @EnableMethodSecurity, oauth2Login.successHandler`.

**Config:** `jwt.secret` env 256-bit, `jwt.access-expiration=900000`, `jwt.refresh-expiration=604800000`, `app.lockout.threshold=5`, `duration=15`, `spring.data.redis.host=localhost:6379`.

---

## 7. Validation & Error Handling (Global)

**DTO record @Valid:** `RegisterRequest @NotBlank @Email / @Size8 / @Size2-100` + `@Valid` in controller -> `MethodArgumentNotValidException` 400.

| Case | Check | Exception | HTTP |
| :--- | :--- | :--- | :--- |
| Duplicate email/role | existsByEmail | DuplicateResourceException | 409 |
| Not found | findByHash orElseThrow | ResourceNotFoundException | 404 |
| Invalid credentials | !matches | BusinessException | 401 |
| Account locked | User.isLocked() | AccountLockedException | 423 |
| Refresh/verify/reset invalid | revoked/expired/used | BusinessException | 400/401 |
| RBAC fail | @PreAuthorize | AuthorizationDeniedException | 403 |
| JWT invalid/revoked | validate / blacklist | 401 JSON from filter | 401 |
| Unexpected | catch all | Exception log.error | 500 |

DB `UNIQUE` -> `DataIntegrityViolationException` -> 409. `GlobalExceptionHandler` returns `ApiResponse{success:false}`.

---

## 8. Coding Standards — Intl + OOP + Ponytail

- **Intl:** single `@RestController` / `@Service` (no interface with one impl), service returns DTO, controller returns `ResponseEntity<ApiResponse<T>>`, record DTO immutable, `@ResponseStatus` not needed (ResponseEntity status).
- **OOP rich domain:** `User` no public `@Setter`, `BaseEntity` protected setId, `User.create()`, `isLocked()/recordFailedAttempt()/resetLockout()/assignRole()/verifyEmail()`, `Role.addPermission()`, `Permission` immutable.
- **DRY:** BaseEntity, ApiResponse, MapperUtil, JwtService, GlobalHandler — 1 place.
- **Logging:** @Slf4j + LoggingAspect `@Around *Service` + MDC requestId in filter.
- **Query:** LAZY, existsBy, JOIN FETCH, Pageable, indexes.
- **Transaction:** @Transactional in service, readOnly for gets, @Modifying for deleteByExpiresAtBefore.
- **Hashing:** BCrypt12 + SHA-256.
- **Validation:** record + Jakarta, BusinessException.
- **Ponytail:** without Redis still works (blacklist fallback map), email mock log, GeoIP mock (ID/Jakarta local), add when prod needs. No Flyway (ddl-auto=update), no MapStruct.

---

## 9. Definition of Done — Fase 1-4B (updated)

- [x] Register/Login/Refresh/Logout JWT 15m+jti + refresh rotate 7d SHA-256
- [x] RBAC seed ROLE_ADMIN/USER + 6 perms, @PreAuthorize, JOIN FETCH anti N+1
- [x] Global Handler + ApiResponse 400/401/403/404/409/423 + record validation
- [x] Email verify 24h + resend, Password reset 60m + revoke refresh
- [x] Redis blacklist jti + UserSession + LoginAttempt async + Scheduler cleanup + 401 after logout verified
- [x] OAuth2 Google link/create, JWT after OAuth
- [x] Risk scoring (IP+device+hour+fails) + suspicious flag + risk in LoginResponse
- [x] Access Risk dashboard `GET /admin/risk-analysis` hasRole ADMIN
- [x] Swagger bearerAuth + README, 56 tests BUILD SUCCESS, intl standard + rich OOP
- [ ] Postman/curl manual demo (next polish)

---

## 10. Next Steps

1. Manual demo via Swagger `/swagger-ui.html`
2. Fase 4 full ML: Anomaly (isolation forest) + Assistant (OpenRouter LLM RAG over PRD + attempts)
3. Prod: Flyway, real SMTP, GeoLite2-City.mmdb, Testcontainers
4. Frontend redirect for OAuth2 (currently JSON)

> **Ponytail:** Fase 1-4B mock-first, real infra only when needed. 56 tests, single controller/service, rich domain, international standard.
