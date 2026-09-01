package com.example.access_management.auth.service;

import com.example.access_management.auth.dto.LoginRequest;
import com.example.access_management.auth.dto.LoginResponse;
import com.example.access_management.auth.dto.RefreshRequest;
import com.example.access_management.auth.dto.RegisterRequest;
import com.example.access_management.auth.entity.RefreshToken;
import com.example.access_management.auth.repository.RefreshTokenRepository;
import com.example.access_management.common.exception.AccountLockedException;
import com.example.access_management.common.exception.BusinessException;
import com.example.access_management.common.exception.DuplicateResourceException;
import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.util.MapperUtil;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.RoleRepository;
import com.example.access_management.security.jwt.JwtService;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

  private final UserRepository userRepository;
  private final RefreshTokenRepository refreshTokenRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;

  @Value("${jwt.access-expiration}")
  private long accessExp;

  @Value("${jwt.refresh-expiration}")
  private long refreshExp;

  @Value("${app.lockout.threshold:5}")
  private int lockoutThreshold;

  @Value("${app.lockout.duration-minutes:15}")
  private long lockoutDurationMinutes;

  @Override
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
    User user = User.builder()
        .email(req.email())
        .passwordHash(passwordEncoder.encode(req.password()))
        .fullName(req.fullName())
        .roles(Set.of(role))
        .build();
    user = userRepository.save(user);
    // ensure roles are loaded for mapper (builder sets HashSet)
    return MapperUtil.toUserResponse(user);
  }

  @Override
  @Transactional
  public LoginResponse login(LoginRequest req) {
    log.debug("login {}", req.email());
    User user = userRepository.findByEmailWithRolesAndPermissions(req.email())
        .orElseThrow(() -> new BusinessException("Invalid credentials"));

    if (user.getLockoutUntil() != null && user.getLockoutUntil().isAfter(Instant.now())) {
      throw new AccountLockedException("Account locked until " + user.getLockoutUntil());
    }

    if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
      int attempts = user.getFailedAttempts() + 1;
      user.setFailedAttempts(attempts);
      if (attempts >= lockoutThreshold) {
        user.setLockoutUntil(Instant.now().plusSeconds(lockoutDurationMinutes * 60));
      }
      userRepository.save(user);
      throw new BusinessException("Invalid credentials");
    }

    // success -> reset
    user.setFailedAttempts(0);
    user.setLockoutUntil(null);
    userRepository.save(user);

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
    return new LoginResponse(accessToken, rawRefresh, accessExp, "Bearer");
  }

  @Override
  @Transactional
  public LoginResponse refresh(RefreshRequest req) {
    String hash = sha256(req.refreshToken());
    RefreshToken token = refreshTokenRepository.findByTokenHash(hash)
        .orElseThrow(() -> new BusinessException("Invalid refresh token"));
    if (token.isRevoked() || token.getExpiresAt().isBefore(Instant.now())) {
      throw new BusinessException("Invalid refresh token");
    }
    // revoke old
    token.setRevoked(true);
    refreshTokenRepository.save(token);

    User user = userRepository.findByEmailWithRolesAndPermissions(token.getUser().getEmail())
        .orElseGet(() -> userRepository.findByIdWithRoles(token.getUser().getId())
            .orElseThrow(() -> new ResourceNotFoundException("User not found")));
    // also need permissions fetched; the above join fetch covers it. Fallback load if needed
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
    return new LoginResponse(accessToken, rawRefresh, accessExp, "Bearer");
  }

  @Override
  @Transactional
  public void logout(RefreshRequest req) {
    String hash = sha256(req.refreshToken());
    refreshTokenRepository.findByTokenHash(hash).ifPresent(rt -> {
      rt.setRevoked(true);
      refreshTokenRepository.save(rt);
    });
  }

  @Override
  @Transactional(readOnly = true)
  public UserResponse me(String email) {
    User user = userRepository.findByEmailWithRolesAndPermissions(email)
        .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(user);
  }

  static String sha256(String token) {
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
