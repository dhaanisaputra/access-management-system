package com.example.access_management.ai.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.ZoneId;

@Configuration
public class RiskConfig {
  @Bean
  public Clock clock() {
    return Clock.system(ZoneId.of("Asia/Jakarta"));
  }
}
