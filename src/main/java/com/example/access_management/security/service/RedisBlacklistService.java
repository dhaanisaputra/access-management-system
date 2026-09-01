package com.example.access_management.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisBlacklistService {

  private final RedisTemplate<String, String> redisTemplate;
  // ponytail: in-memory fallback when Redis unavailable (tests / local without Redis)
  private final ConcurrentMap<String, Instant> fallback = new ConcurrentHashMap<>();

  private static String key(String jti) {
    return "blacklist:" + jti;
  }

  public void blacklist(String jti, long ttlSeconds) {
    if (jti == null || ttlSeconds <= 0) return;
    fallback.put(jti, Instant.now().plusSeconds(ttlSeconds));
    try {
      redisTemplate.opsForValue().set(key(jti), "1", ttlSeconds, TimeUnit.SECONDS);
    } catch (Exception e) {
      log.warn("Redis blacklist set failed for jti={}: {}", jti, e.getMessage());
    }
  }

  public boolean isBlacklisted(String jti) {
    if (jti == null) return false;
    try {
      Boolean has = redisTemplate.hasKey(key(jti));
      if (Boolean.TRUE.equals(has)) return true;
    } catch (Exception e) {
      log.warn("Redis blacklist check failed for jti={}: {}", jti, e.getMessage());
    }
    Instant exp = fallback.get(jti);
    if (exp != null) {
      if (exp.isAfter(Instant.now())) return true;
      fallback.remove(jti);
    }
    return false;
  }
}
