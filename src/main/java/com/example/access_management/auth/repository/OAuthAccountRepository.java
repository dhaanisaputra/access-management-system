package com.example.access_management.auth.repository;

import com.example.access_management.auth.entity.OAuthAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OAuthAccountRepository extends JpaRepository<OAuthAccount, Long> {
  Optional<OAuthAccount> findByProviderAndProviderUserId(String provider, String providerUserId);
  List<OAuthAccount> findByEmail(String email);
  List<OAuthAccount> findByUserId(Long userId);
}
