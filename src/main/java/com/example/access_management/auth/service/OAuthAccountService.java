package com.example.access_management.auth.service;

import com.example.access_management.auth.entity.OAuthAccount;
import com.example.access_management.auth.repository.OAuthAccountRepository;
import com.example.access_management.role.entity.Role;
import com.example.access_management.role.repository.RoleRepository;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class OAuthAccountService {

  private final OAuthAccountRepository oAuthAccountRepository;
  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;

  public User processOAuthUser(String provider, String providerUserId, String email, String fullName) {
    log.debug("processOAuthUser provider={} providerUserId={} email={}", provider, providerUserId, email);

    // 1. existing link -> return linked user
    var existing = oAuthAccountRepository.findByProviderAndProviderUserId(provider, providerUserId);
    if (existing.isPresent()) {
      return existing.get().getUser();
    }

    // 2. existing user by email -> link
    if (email != null) {
      var userOpt = userRepository.findByEmail(email);
      if (userOpt.isPresent()) {
        User user = userOpt.get();
        ensureEmailVerified(user);
        OAuthAccount acc = OAuthAccount.builder()
            .provider(provider)
            .providerUserId(providerUserId)
            .email(email)
            .user(user)
            .build();
        oAuthAccountRepository.save(acc);
        log.info("Linked oauth {}:{} to existing user {}", provider, providerUserId, email);
        return user;
      }
    }

    // 3. new user
    Role role = roleRepository.findByName("ROLE_USER").orElseGet(() -> {
      log.debug("ROLE_USER not found, creating");
      return roleRepository.save(Role.builder().name("ROLE_USER").description("Default user").build());
    });

    String displayName = (fullName != null && !fullName.isBlank()) ? fullName : (email != null ? email : providerUserId);
    String randomHash = passwordEncoder.encode(UUID.randomUUID().toString());
    String safeEmail = email != null ? email : provider + "_" + providerUserId + "@oauth.local";

    User user = User.create(safeEmail, randomHash, displayName, Set.of(role));
    user.verifyEmail();
    user = userRepository.save(user);

    OAuthAccount acc = OAuthAccount.builder()
        .provider(provider)
        .providerUserId(providerUserId)
        .email(email)
        .user(user)
        .build();
    oAuthAccountRepository.save(acc);
    log.info("Created new user {} for oauth {}:{}", safeEmail, provider, providerUserId);
    return user;
  }

  private void ensureEmailVerified(User user) {
    if (!user.isEmailVerified()) {
      user.verifyEmail();
      userRepository.save(user);
    }
  }
}
