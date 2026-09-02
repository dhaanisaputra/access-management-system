package com.example.access_management.ai.service;

import com.example.access_management.ai.dto.RiskAnalysisResponse;
import com.example.access_management.ai.dto.RiskAnalysisResponse.PermissionRiskDto;
import com.example.access_management.ai.dto.RiskAnalysisResponse.UserRiskDto;
import com.example.access_management.auth.entity.UserSession;
import com.example.access_management.auth.repository.LoginAttemptRepository;
import com.example.access_management.auth.repository.UserSessionRepository;
import com.example.access_management.user.entity.User;
import com.example.access_management.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AccessRiskAnalysisService {

  private final UserRepository userRepository;
  private final UserSessionRepository userSessionRepository;
  private final LoginAttemptRepository loginAttemptRepository;
  private final Clock clock;

  @Transactional(readOnly = true)
  public RiskAnalysisResponse analyze() {
    List<User> users = userRepository.findAll();
    int total = users.size();

    List<UserRiskDto> allRisks = new ArrayList<>();
    int high = 0, medium = 0, low = 0;

    for (User u : users) {
      UserRiskDto dto = calculateForUser(u);
      allRisks.add(dto);
      switch (dto.riskLevel()) {
        case "HIGH" -> high++;
        case "MEDIUM" -> medium++;
        default -> low++;
      }
    }

    allRisks.sort(Comparator.comparingInt(UserRiskDto::riskScore).reversed());
    List<UserRiskDto> top = allRisks.stream().limit(10).toList();

    List<String> riskyPerms = List.of("role:assign", "user:delete", "user:create");
    List<PermissionRiskDto> permRisks = new ArrayList<>();
    for (String perm : riskyPerms) {
      List<User> withPerm;
      try {
        withPerm = userRepository.findByPermissionName(perm);
      } catch (Exception e) {
        // fallback: manual filter if query fails (e.g., lazy)
        withPerm = users.stream()
            .filter(user -> user.getRoles().stream()
                .flatMap(r -> r.getPermissions().stream())
                .anyMatch(p -> p.getName().equals(perm)))
            .toList();
      }
      List<String> emails = withPerm.stream().map(User::getEmail).toList();
      permRisks.add(new PermissionRiskDto(perm, withPerm.size(), emails));
    }

    return new RiskAnalysisResponse(total, high, medium, low, top, permRisks);
  }

  // ponytail: helper compares last 2 sessions + fails + hour, covers all users in one place
  private UserRiskDto calculateForUser(User user) {
    Long userId = user.getId();
    String email = user.getEmail();

    List<UserSession> sessions = userSessionRepository.findByUserId(userId);
    sessions.sort(Comparator.comparing(UserSession::getLastActive).reversed());

    UserSession latest = sessions.isEmpty() ? null : sessions.get(0);
    String lastIp = latest != null ? latest.getIpAddress() : null;
    String lastUa = latest != null ? latest.getUserAgent() : null;
    Instant lastLoginAt = latest != null ? latest.getLastActive() : null;

    if (lastIp == null) {
      var opt = loginAttemptRepository.findTopByEmailOrderByAttemptedAtDesc(email);
      if (opt.isPresent()) {
        lastIp = opt.get().getIpAddress();
        lastLoginAt = opt.get().getAttemptedAt();
      }
    }

    int score = 0;
    List<String> reasons = new ArrayList<>();

    if (sessions.size() >= 2) {
      String ip1 = sessions.get(0).getIpAddress();
      String ip2 = sessions.get(1).getIpAddress();
      if (ip1 != null && ip2 != null && !ip1.equals(ip2)) {
        score += 40;
        reasons.add("IP changed from " + ip2 + " to " + ip1);
      }
      String ua1 = sessions.get(0).getUserAgent();
      String ua2 = sessions.get(1).getUserAgent();
      if (ua1 != null && ua2 != null && !ua1.equals(ua2)) {
        score += 30;
        reasons.add("Device/UserAgent changed");
      }
    }

    long fails = loginAttemptRepository.countByEmailAndSuccessFalseAndAttemptedAtAfter(email, Instant.now(clock).minusSeconds(3600));
    if (fails > 3) {
      score += 20;
      reasons.add("Multiple failed attempts in last hour: " + fails);
    }

    int hour = Instant.now(clock).atZone(ZoneId.of("Asia/Jakarta")).getHour();
    if (hour < 6 || hour > 22) {
      score += 10;
      reasons.add("Login outside normal hours (" + hour + "h Asia/Jakarta)");
    }

    String level = score < 40 ? "LOW" : score <= 70 ? "MEDIUM" : "HIGH";
    return new UserRiskDto(userId, email, user.getFullName(), score, level, lastIp, lastLoginAt, List.copyOf(reasons));
  }
}
