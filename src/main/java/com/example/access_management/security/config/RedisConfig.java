package com.example.access_management.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

  @Bean
  RedisTemplate<String, String> redisTemplate(RedisConnectionFactory factory) {
    RedisTemplate<String, String> template = new RedisTemplate<>();
    template.setConnectionFactory(factory);
    StringRedisSerializer ser = new StringRedisSerializer();
    template.setKeySerializer(ser);
    template.setValueSerializer(ser);
    template.setHashKeySerializer(ser);
    template.setHashValueSerializer(ser);
    template.afterPropertiesSet();
    return template;
  }
}
