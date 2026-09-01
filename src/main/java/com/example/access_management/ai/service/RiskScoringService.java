package com.example.access_management.ai.service;

import com.example.access_management.auth.repository.LoginAttemptRepository;
import com.example.access_management.auth.repository.UserSessionRepository;
import com.example.access_management.user.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class RiskScoringService {

  private final LoginAttemptRepository loginAttemptRepository;
  private final UserSessionRepository userSessionRepository;
  private final UserRepository userRepository;
  private final Clock clock;

  public RiskScoringService(LoginAttemptRepository loginAttemptRepository,
                            UserSessionRepository userSessionRepository,
                            UserRepository userRepository,
                            Clock clock) {
    this.loginAttemptRepository = loginAttemptRepository;
    this.userSessionRepository = userSessionRepository;
    this.userRepository = userRepository;
    this.clock = clock != null ? clock : Clock.system(ZoneId.of("Asia/Jakarta"));
  }

  public record RiskResult(int score, String level, List<String> reasons, boolean suspicious) {}

  public RiskResult calculateRisk(String email, String ip, String userAgent) {
    int score = 0;
    List<String> reasons = new ArrayList<>();

    var lastAttempt = loginAttemptRepository.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc(email);
    String lastIp = lastAttempt.map(a -> a.getIpAddress()).orElse(null);

    // Try UserSession for UA baseline if user exists
    String lastUa = null;
    try {
      var userOpt = userRepository.findByEmail(email);
      if (userOpt.isPresent()) {
        var sessOpt = userSessionRepository.findTopByUserIdAndIsActiveTrueOrderByLastActiveDesc(userOpt.get().getId());
        if (sessOpt.isPresent()) {
          lastUa = sessOpt.get().getUserAgent();
          if (lastIp == null) lastIp = sessOpt.get().getIpAddress();
        }
      }
    } catch (Exception ignored) {}

    if (lastIp != null && ip != null && !ip.equals(lastIp)) {
      score += 40;
      reasons.add("IP changed from " + lastIp + " to " + ip);
    }

    if (lastUa != null && userAgent != null && !userAgent.equals(lastUa)) {
      score += 30;
      reasons.add("Device/UserAgent changed");
    } else if (lastUa == null && lastAttempt.isPresent() && userAgent != null && !userAgent.isBlank()) {
      // No UA history yet — don't penalize first UA, only when session exists.
      // ponytail: UA scoring requires UserSession baseline; without it we skip to avoid false positives
    }

    int hour = Instant.now(clock).atZone(ZoneId.of("Asia/Jakarta")).getHour();
    if (hour < 6 || hour > 22) {
      score += 10;
      reasons.add("Login outside normal hours (" + hour + "h Asia/Jakarta)");
    }

    long fails = loginAttemptRepository.countByEmailAndSuccessFalseAndAttemptedAtAfter(email, Instant.now(clock).minusSeconds(3600));
    if (fails > 3) {
      score += 20;
      reasons.add("Multiple failed attempts in last hour: " + fails);
    }

    String level = score < 40 ? "LOW" : score <= 70 ? "MEDIUM" : "HIGH";
    boolean suspicious = score >= 40;
    log.debug("risk email={} ip={} score={} level={}", email, ip, score, level);
    return new RiskResult(score, level, List.copyOf(reasons), suspicious);
  }

  // Test helper for explicit UA baseline without needing UserSession row
  public RiskResult calculateRisk(String email, String ip, String userAgent, String lastUserAgent) {
    var base = calculateRisk(email, ip, userAgent);
    boolean alreadyDevice = base.reasons().stream().anyMatch(r -> r.contains("Device"));
    if (!alreadyDevice && lastUserAgent != null && userAgent != null && !userAgent.equals(lastUserAgent)) {
      int newScore = base.score() + 30;
      List<String> nr = new ArrayList<>(base.reasons());
      nr.add("Device/UserAgent changed");
      String level = newScore < 40 ? "LOW" : newScore <= 70 ? "MEDIUM" : "HIGH";
      return new RiskResult(newScore, level, List.copyOf(nr), newScore >= 40);
    }
    return base;
  }
}
