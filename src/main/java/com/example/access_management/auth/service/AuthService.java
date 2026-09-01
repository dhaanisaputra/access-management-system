package com.example.access_management.auth.service;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.dto.ResetPasswordRequest;
import com.example.access_management.auth.entity.EmailVerificationToken;
import com.example.access_management.auth.entity.PasswordResetToken;
import com.example.access_management.auth.entity.RefreshToken;
import com.example.access_management.auth.repository.EmailVerificationTokenRepository;
import com.example.access_management.auth.repository.PasswordResetTokenRepository;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import com.example.access_management.common.exception.AccountLockedException;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.exception.DuplicateResourceException;
import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.service.EmailService;
import com.example.access_management.common.util.MapperUtil;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.RoleRepository;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import com.example.access_management.ai.service.GeoIpService;
import com.example.access_management.ai.service.RiskScoringService;
import com.example.access_management.auth.entity.LoginAttempt;
import com.example.access_management.auth.entity.UserSession;
import com.example.access_management.auth.repository.LoginAttemptRepository;
import com.example.access_management.auth.repository.UserSessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final EmailVerificationTokenRepository emailVerificationTokenRepository;
  private final PasswordResetTokenRepository passwordResetTokenRepository;
  private final LoginAttemptRepository loginAttemptRepository;
  private final UserSessionRepository userSessionRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final EmailService emailService;
  private final RiskScoringService riskScoringService;
  private final GeoIpService geoIpService;

  private AuthService self;

  @Autowired
  public void setSelf(@Lazy AuthService self) {
    this.self = self;
  }

  @Value("${jwt.access-expiration}")
  private long accessExp;

  @Value("${jwt.refresh-expiration}")
  private long refreshExp;

  @Value("${app.lockout.threshold:5}")
  private int lockoutThreshold;

  @Value("${app.lockout.duration-minutes:15}")
  private long lockoutDurationMinutes;

  @Transactional
  public UserResponse register(RegisterRequest req) {
    log.debug("register {}", req.email());
    if (userRepository.existsByEmail(req.email())) {
      throw new DuplicateResourceException("Email already exists: " + req.email());
    }
    Role role = roleRepository.findByName("ROLE_USER").orElseGet(() -> {
      log.debug("ROLE_USER not found, creating");
      Role r = Role.builder().name("ROLE_USER").description("Default user").build();
      return roleRepository.save(r);
    });
    User user = User.create(req.email(), passwordEncoder.encode(req.password()), req.fullName(), Set.of(role));
    user = userRepository.save(user);
    String rawToken = UUID.randomUUID().toString();
    String hash = sha256(rawToken);
    EmailVerificationToken evt = EmailVerificationToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(Instant.now().plusSeconds(86400))
        .used(false)
        .build();
    emailVerificationTokenRepository.save(evt);
    emailService.sendVerification(user.getEmail(), rawToken);
    return MapperUtil.toUserResponse(user);
  }

  @Transactional
  public UserResponse verifyEmail(String rawToken) {
    String hash = sha256(rawToken);
    EmailVerificationToken evt = emailVerificationTokenRepository.findByTokenHash(hash)
        .orElseThrow(() -> new BusinessException("Invalid verification token"));
    if (evt.isUsed() || evt.isExpired()) {
      throw new BusinessException("Invalid or expired verification token");
    }
    evt.markUsed();
    emailVerificationTokenRepository.save(evt);
    User user = evt.getUser();
    user.verifyEmail();
    userRepository.save(user);
    return MapperUtil.toUserResponse(user);
  }

  @Transactional
  public void resendVerification(String email) {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + email));
    if (user.isEmailVerified()) {
      throw new BusinessException("Email already verified");
    }
    var existing = emailVerificationTokenRepository.findByUserIdAndUsedFalse(user.getId());
    if (!existing.isEmpty()) {
      emailVerificationTokenRepository.deleteAll(existing);
      emailVerificationTokenRepository.flush();
    }
    String rawToken = UUID.randomUUID().toString();
    String hash = sha256(rawToken);
    EmailVerificationToken evt = EmailVerificationToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(Instant.now().plusSeconds(86400))
        .used(false)
        .build();
    emailVerificationTokenRepository.save(evt);
    emailService.sendVerification(user.getEmail(), rawToken);
  }

  @Transactional
  public LoginResponse login(LoginRequest req) {
    log.debug("login {}", req.email());
    String ip = resolveIp();
    String userAgent = resolveUserAgent();
    User user = userRepository.findByEmailWithRolesAndPermissions(req.email()).orElse(null);
    if (user == null) {
      try { if (self != null) self.recordLoginAttempt(req.email(), ip, false); else recordLoginAttempt(req.email(), ip, false); } catch (Exception ignored) {}
      throw new BusinessException("Invalid credentials");
    }

    if (user.isLocked()) {
      try { if (self != null) self.recordLoginAttempt(req.email(), ip, false); else recordLoginAttempt(req.email(), ip, false); } catch (Exception ignored) {}
      throw new AccountLockedException("Account locked until " + user.getLockoutUntil());
    }

    if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
      user.recordFailedAttempt(lockoutThreshold, lockoutDurationMinutes);
      userRepository.save(user);
      try { if (self != null) self.recordLoginAttempt(req.email(), ip, false); else recordLoginAttempt(req.email(), ip, false); } catch (Exception ignored) {}
      throw new BusinessException("Invalid credentials");
    }

    user.resetLockout();
    userRepository.save(user);

    // ponytail: risk scoring + UserSession for every successful login
    RiskScoringService.RiskResult risk = null;
    try {
      risk = riskScoringService.calculateRisk(req.email(), ip, userAgent);
      if ("HIGH".equals(risk.level())) {
        log.warn("suspicious login email={} ip={} ua={} score={} reasons={}", req.email(), ip, userAgent, risk.score(), risk.reasons());
      } else if ("MEDIUM".equals(risk.level())) {
        log.info("medium-risk login email={} ip={} score={} reasons={}", req.email(), ip, risk.score(), risk.reasons());
      } else {
        log.debug("risk email={} score={} level={}", req.email(), risk.score(), risk.level());
      }
    } catch (Exception e) {
      log.warn("risk scoring failed for {}: {}", req.email(), e.getMessage());
      risk = new RiskScoringService.RiskResult(0, "LOW", List.of(), false);
    }

    // save UserSession
    try {
      GeoIpService.GeoResult geo = geoIpService.lookup(ip);
      String[] parsed = parseUa(userAgent);
      UserSession session = UserSession.builder()
          .user(user)
          .ipAddress(ip)
          .userAgent(userAgent)
          .country(geo.country())
          .city(geo.city())
          .device(parsed[0])
          .os(parsed[1])
          .browser(parsed[2])
          .lastActive(Instant.now())
          .isActive(true)
          .build();
      userSessionRepository.save(session);
    } catch (Exception e) {
      log.warn("failed to save UserSession for {}: {}", req.email(), e.getMessage());
    }

    String accessToken = jwtService.generateAccessToken(user);
    String rawRefresh = UUID.randomUUID().toString();
    String hash = sha256(rawRefresh);
    RefreshToken rt = RefreshToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(Instant.now().plusMillis(refreshExp))
        .revoked(false)
        .build();
    refreshTokenRepository.save(rt);
    try { if (self != null) self.recordLoginAttempt(req.email(), ip, true); else recordLoginAttempt(req.email(), ip, true); } catch (Exception ignored) {}
    if (risk == null) risk = new RiskScoringService.RiskResult(0, "LOW", List.of(), false);
    return new LoginResponse(accessToken, rawRefresh, accessExp, "Bearer", risk.score(), risk.level(), risk.suspicious(), risk.reasons());
  }

  @Async
  public void recordLoginAttempt(String email, String ipAddress, boolean success) {
    try {
      LoginAttempt attempt = LoginAttempt.builder()
          .email(email)
          .ipAddress(ipAddress != null ? ipAddress : "unknown")
          .success(success)
          .attemptedAt(Instant.now())
          .build();
      loginAttemptRepository.save(attempt);
    } catch (Exception e) {
      log.warn("Failed to record login attempt for {}: {}", email, e.getMessage());
    }
  }

  private String resolveIp() {
    try {
      var attrs = RequestContextHolder.getRequestAttributes();
      if (attrs instanceof ServletRequestAttributes sra) {
        HttpServletRequest req = sra.getRequest();
        String ip = req.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isBlank()) return ip.split(",")[0].trim();
        return req.getRemoteAddr();
      }
    } catch (Exception ignored) {}
    return "unknown";
  }

  private String resolveUserAgent() {
    try {
      var attrs = RequestContextHolder.getRequestAttributes();
      if (attrs instanceof ServletRequestAttributes sra) {
        String ua = sra.getRequest().getHeader("User-Agent");
        if (ua != null && !ua.isBlank()) return ua;
        return sra.getRequest().getHeader("user-agent");
      }
    } catch (Exception ignored) {}
    return null;
  }

  // ponytail: lazy ua-parser, naive fallback to avoid extra bean
  private String[] parseUa(String ua) {
    String device = "Unknown", os = "Unknown", browser = "Unknown";
    if (ua != null && !ua.isBlank()) {
      try {
        ua_parser.Parser parser = new ua_parser.Parser();
        ua_parser.Client c = parser.parse(ua);
        if (c.device != null && c.device.family != null) device = c.device.family;
        if (c.os != null && c.os.family != null) os = c.os.family;
        if (c.userAgent != null && c.userAgent.family != null) browser = c.userAgent.family;
      } catch (Exception e) {
        // fallback: first token
        device = ua.length() > 80 ? ua.substring(0, 80) : ua;
      }
    }
    return new String[]{device, os, browser};
  }

  @Transactional
  public LoginResponse refresh(RefreshRequest req) {
    String hash = sha256(req.refreshToken());
    RefreshToken token = refreshTokenRepository.findByTokenHash(hash)
        .orElseThrow(() -> new BusinessException("Invalid refresh token"));
    if (token.isRevoked() || token.getExpiresAt().isBefore(Instant.now())) {
      throw new BusinessException("Invalid refresh token");
    }
    token.setRevoked(true);
    refreshTokenRepository.save(token);

    User user = userRepository.findByEmailWithRolesAndPermissions(token.getUser().getEmail())
        .orElseGet(() -> userRepository.findByIdWithRoles(token.getUser().getId())
            .orElseThrow(() -> new ResourceNotFoundException("User not found")));
    String accessToken = jwtService.generateAccessToken(user);
    String rawRefresh = UUID.randomUUID().toString();
    String newHash = sha256(rawRefresh);
    RefreshToken newToken = RefreshToken.builder()
        .user(user)
        .tokenHash(newHash)
        .expiresAt(Instant.now().plusMillis(refreshExp))
        .revoked(false)
        .build();
    refreshTokenRepository.save(newToken);
    return new LoginResponse(accessToken, rawRefresh, accessExp, "Bearer", 0, "LOW", false, List.of());
  }

  @Transactional
  public void logout(RefreshRequest req) {
    String hash = sha256(req.refreshToken());
    refreshTokenRepository.findByTokenHash(hash).ifPresent(rt -> {
      rt.setRevoked(true);
      refreshTokenRepository.save(rt);
    });
  }

  @Transactional
  public void forgotPassword(String email) {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new BusinessException("User not found: " + email));
    String rawToken = UUID.randomUUID().toString();
    String hash = sha256(rawToken);
    PasswordResetToken prt = PasswordResetToken.builder()
        .user(user)
        .tokenHash(hash)
        .expiresAt(Instant.now().plusSeconds(3600))
        .used(false)
        .build();
    passwordResetTokenRepository.save(prt);
    emailService.sendPasswordReset(user.getEmail(), rawToken);
  }

  @Transactional
  public void resetPassword(ResetPasswordRequest req) {
    String hash = sha256(req.token());
    PasswordResetToken prt = passwordResetTokenRepository.findByTokenHash(hash)
        .orElseThrow(() -> new BusinessException("Invalid reset token"));
    if (prt.isUsed() || prt.isExpired()) {
      throw new BusinessException("Invalid or expired reset token");
    }
    User user = prt.getUser();
    user.changePasswordHash(passwordEncoder.encode(req.newPassword()));
    userRepository.save(user);
    prt.markUsed();
    passwordResetTokenRepository.save(prt);
    // revoke all active refresh tokens
    var active = refreshTokenRepository.findByUserIdAndRevokedFalse(user.getId());
    for (var rt : active) {
      rt.setRevoked(true);
    }
    if (!active.isEmpty()) {
      refreshTokenRepository.saveAll(active);
    }
  }

  @Transactional(readOnly = true)
  public UserResponse me(String email) {
    User user = userRepository.findByEmailWithRolesAndPermissions(email)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(user);
  }

  public static String sha256(String token) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
      StringBuilder hex = new StringBuilder(hash.length * 2);
      for (byte b : hash) hex.append(String.format("%02x", b));
      return hex.toString();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
