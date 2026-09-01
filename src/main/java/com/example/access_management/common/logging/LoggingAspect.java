package com.example.access_management.common.logging;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class LoggingAspect {

  @Around("execution(* com.example.access_management..*ServiceImpl.*(..))")
  public Object log(ProceedingJoinPoint pjp) throws Throwable {
    String method = pjp.getSignature().toShortString();
    long start = System.currentTimeMillis();
    try {
      Object r = pjp.proceed();
      log.debug("{} -> {} ms", method, System.currentTimeMillis() - start);
      return r;
    } catch (Throwable ex) {
      log.error("{} failed after {} ms: {}", method, System.currentTimeMillis() - start, ex.getMessage());
      throw ex;
    }
  }
}
