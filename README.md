# Identity & Access Management Platform (Auth0/Octa Mini)

> Simplified Auth0/Okta-style identity service — **Java 25 + Spring Boot 4.1.1 + Spring Security + PostgreSQL + Redis**

**Resume Value:** ★★★★★ — Security reusable untuk hampir semua backend.

## Key Features (Fase 1-4 Done)

| Fase | Feature | Status |
|------|---------|--------|
| **1 MVP** | User registration, Login/logout, JWT 15m + refresh 7d rotate (R1 opaque), RBAC Role+Permission, BCrypt(12), API security | ✅ 18 tests |
| **2** | Email verification (24h), Password reset (60m), Redis blacklist (jti), Session + Login attempts audit, Scheduler cleanup | ✅ 35 tests |
| **3** | OAuth2 Google login (oauth_accounts), link by email, issue JWT | ✅ 45 tests |
| **4B** | Suspicious Login Detection, Risk-Based Auth (rule-based), Access Risk Analysis dashboard | ✅ 56 tests |

**AI Features (mock):** Suspicious = IP/device change +40/+30, Risk score 0-100 → LOW/MEDIUM/HIGH, dashboard `/api/v1/admin/risk-analysis`.

## Tech Stack

- Java 25, Spring Boot 4.1.1 (webmvc, data-jpa, security, validation, data-redis, oauth2-client)
- PostgreSQL `access_management_platform` (HikariCP), H2 test, Redis 7 (6379)
- JJWT 0.12.5 (HS256), BCrypt(12), SHA-256 refresh tokens, springdoc-openapi 2.8.5
- Lombok, MapStruct-less manual mapper, AOP logging

## Architecture

```
com.example.access_management
├─ auth/         (register/login/refresh/logout/verify/forgot/reset)
├─ user/         (User rich domain: isLocked/recordFailedAttempt/resetLockout)
├─ role/         (Role/Permission, many-to-many)
├─ security/     (JwtService, JwtAuthFilter, SecurityConfig, RedisBlacklist, OAuth2SuccessHandler)
├─ ai/           (RiskScoringService, AccessRiskAnalysis)
└─ common/       (BaseEntity, ApiResponse<T>, GlobalExceptionHandler, EmailService mock, LoggingAspect)
```

**Standard:** Intl — single `@RestController` + `@Service`, service returns DTO (not ResponseEntity), controller returns `ResponseEntity<ApiResponse<T>>`, record DTO, rich domain (no public setters).

## Quick Start

```bash
# 1. Infra
docker run -d --name postgres -e POSTGRES_DB=access_management_platform -e POSTGRES_USER=admin -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
docker run -d --name redis -p 6379:6379 redis:7

# 2. Env (optional)
export GOOGLE_CLIENT_ID=xxx && export GOOGLE_CLIENT_SECRET=yyy
export JWT_SECRET=change-me-to-256-bit-secret-key-at-least-32-chars-long-please

# 3. Run
./mvnw spring-boot:run  # http://localhost:8080

# 4. Test
./mvnw test  # 56 tests, BUILD SUCCESS
```

## API Contract (prefix `/api/v1`)

**Auth (public)**
```
POST /auth/register        {email, password, fullName} -> 201 ApiResponse<UserResponse>
POST /auth/login           {email, password} -> 200 LoginResponse{accessToken, refreshToken, expiresIn, riskScore, riskLevel, suspicious}
POST /auth/refresh         {refreshToken} -> 200 LoginResponse (rotate)
POST /auth/logout          {refreshToken} + Bearer -> 200 (blacklist jti + revoke refresh)
GET  /auth/me              Bearer -> 200 UserResponse
POST /auth/verify-email    {token} -> 200
POST /auth/resend-verification {email}
POST /auth/forgot-password {email}
POST /auth/reset-password  {token, newPassword}
GET  /oauth2/authorization/google  -> redirect Google
GET  /login/oauth2/code/google    -> JSON LoginResponse (handled by success handler)
```

**User / Role (RBAC)**
```
GET  /users/{id}           hasAuthority('user:read')
GET  /roles                hasRole('ADMIN')
POST /roles                hasAuthority('role:assign') {name, permissionIds}
GET  /admin/risk-analysis  hasRole('ADMIN') -> RiskAnalysisResponse
```

**Response wrapper**
```json
{ "success": true, "message": "Success", "data": { ... }, "timestamp": "2026-09-02T..." }
```

**Swagger:** `http://localhost:8080/swagger-ui.html`, `/api-docs`

## What You'll Learn

Spring Security (filter chain, method security), JWT (15m) + refresh rotate, OAuth2, RBAC, BCrypt, Session (Redis blacklist), Password hashing, API security (401/403/404/409/423 via GlobalExceptionHandler).

## OOP Highlights

- `User.isLocked()`, `recordFailedAttempt(threshold, minutes)`, `resetLockout()`, `User.create()`, `Role.addPermission()` — rich domain, no public setters
- `BaseEntity` `@MappedSuperclass`, `ApiResponse<T>` generic, `LoggingAspect` AOP

## Security Flow (JWT 15m + silent refresh)

1. `POST /login` -> access 15m (JWT `sub=id, email, roles, perms, jti`) + refresh UUID (sha256 in DB 7d)
2. `GET /users` + Bearer -> `JwtAuthFilter` validate + blacklist check + `UserDetails` (JOIN FETCH anti N+1)
3. 401 -> frontend calls `POST /refresh` -> new pair (rotate, revoke old)
4. `POST /logout` -> blacklist jti in Redis TTL=remaining + revoke refresh
5. Risk: `RiskScoringService` scores new IP +40, new device +30, outside hours +10, fails>3 +20

## Project Docs

- `PRD.md` — full roadmap Fase 1-4
- `HELP.md` — Spring guides
- `docs/superpowers/plans/` — ignored via `.gitignore` (local only)

## Next

- Fase 4 full ML (isolation forest), Swagger grouping, frontend redirect for OAuth2.

---

**Ponytail:** Run without Redis still works (blacklist fallback map), email is mock `log.info` — add real SMTP/SendGrid when needed.
