package com.example.access_management.security;

import com.example.access_management.security.service.RedisBlacklistService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisBlacklistServiceTest {

  @Mock RedisTemplate<String, String> redisTemplate;
  @Mock ValueOperations<String, String> valueOps;
  @InjectMocks RedisBlacklistService service;

  @Test
  void blacklist_then_isBlacklisted_true() {
    String jti = "test-jti-123";
    when(redisTemplate.opsForValue()).thenReturn(valueOps);
    when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(true);

    service.blacklist(jti, 900);

    verify(valueOps).set(eq("blacklist:" + jti), eq("1"), eq(900L), eq(TimeUnit.SECONDS));
    assertThat(service.isBlacklisted(jti)).isTrue();
  }

  @Test
  void isBlacklisted_false_when_not_present() {
    String jti = "not-blacklisted";
    when(redisTemplate.hasKey("blacklist:" + jti)).thenReturn(false);
    assertThat(service.isBlacklisted(jti)).isFalse();
  }

  @Test
  void isBlacklisted_false_when_null() {
    assertThat(service.isBlacklisted(null)).isFalse();
  }

  @Test
  void blacklist_noop_when_ttl_zero() {
    service.blacklist("jti", 0);
    verify(redisTemplate, never()).opsForValue();
  }
}
