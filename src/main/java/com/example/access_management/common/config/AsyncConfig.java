package com.example.access_management.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@EnableAsync
public class AsyncConfig {

  @Bean
  TaskExecutor taskExecutor() {
    ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
    exec.setCorePoolSize(2);
    exec.setMaxPoolSize(5);
    exec.setQueueCapacity(100);
    exec.setThreadNamePrefix("async-");
    exec.initialize();
    return exec;
  }
}
