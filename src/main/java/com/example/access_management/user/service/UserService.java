package com.example.access_management.user.service;

import com.example.access_management.common.exception.ResourceNotFoundException;
import com.example.access_management.common.util.MapperUtil;
import com.example.access_management.user.dto.UserResponse;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

  private final UserRepository userRepository;

  @Transactional(readOnly = true)
  public UserResponse getById(Long id) {
    log.debug("getById {}", id);
    var u = userRepository.findByIdWithRoles(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(u);
  }

  @Transactional(readOnly = true)
  public UserResponse getByEmail(String email) {
    var u = userRepository.findByEmailWithRolesAndPermissions(email).orElseThrow(() -> new ResourceNotFoundException("User not found"));
    return MapperUtil.toUserResponse(u);
  }
}
