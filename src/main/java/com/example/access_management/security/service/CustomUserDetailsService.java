package com.example.access_management.security.service;

import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    User u = userRepository.findByEmailWithRolesAndPermissions(email)
        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

    Set<GrantedAuthority> authorities = new HashSet<>();
    u.getRoles().forEach(role -> {
      authorities.add(new SimpleGrantedAuthority(role.getName()));
      role.getPermissions().forEach(perm -> authorities.add(new SimpleGrantedAuthority(perm.getName())));
    });

    boolean accountNonLocked = u.getLockoutUntil() == null || u.getLockoutUntil().isBefore(Instant.now());

    return new org.springframework.security.core.userdetails.User(
        u.getEmail(),
        u.getPasswordHash(),
        u.isEnabled(),
        true,
        true,
        accountNonLocked,
        authorities
    );
  }
}
