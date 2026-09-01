package com.example.access_management.ai;

import com.example.access_management.ai.service.RiskScoringService;
import com.example.access_management.auth.entity.LoginAttempt;
import com.example.access_management.auth.repository.LoginAttemptRepository;
import com.example.access_management.auth.repository.UserSessionRepository;
import com.example.access_management.user.repository.UserRepository;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class RiskScoringServiceTest {

  private LoginAttempt attempt(String ip) {
    return LoginAttempt.builder().email("a@test.com").ipAddress(ip).success(true).attemptedAt(Instant.now()).build();
  }

  private RiskScoringService service(LoginAttemptRepository lar, UserSessionRepository usr, UserRepository ur, Clock clock) {
    return new RiskScoringService(lar, usr, ur, clock);
  }

  private Clock clockAtHour(int hour) {
    Instant instant = java.time.ZonedDateTime.of(2026, 1, 1, hour, 0, 0, 0, ZoneId.of("Asia/Jakarta")).toInstant();
    return Clock.fixed(instant, ZoneId.of("Asia/Jakarta"));
  }

  @Test
  void sameIp_lowRisk() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.of(attempt("1.1.1.1")));
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(anyString(), any())).thenReturn(0L);
    when(ur.findByEmail(anyString())).thenReturn(Optional.empty());

    var svc = service(lar, usr, ur, clockAtHour(10));
    var r = svc.calculateRisk("a@test.com", "1.1.1.1", "Mozilla/5.0");
    assertThat(r.score()).isLessThan(40);
    assertThat(r.level()).isEqualTo("LOW");
    assertThat(r.suspicious()).isFalse();
  }

  @Test
  void newIp_mediumSuspicious() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.of(attempt("1.1.1.1")));
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(anyString(), any())).thenReturn(0L);
    when(ur.findByEmail(anyString())).thenReturn(Optional.empty());

    var svc = service(lar, usr, ur, clockAtHour(10));
    var r = svc.calculateRisk("a@test.com", "2.2.2.2", "Mozilla/5.0");
    assertThat(r.score()).isGreaterThanOrEqualTo(40);
    assertThat(r.suspicious()).isTrue();
    assertThat(r.level()).isIn("MEDIUM", "HIGH");
    assertThat(r.reasons()).anyMatch(s -> s.contains("IP changed"));
  }

  @Test
  void newIpAndUa_high() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.of(attempt("1.1.1.1")));
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(anyString(), any())).thenReturn(0L);
    // need session baseline for UA change
    var user = com.example.access_management.user.entity.User.create("a@test.com", "hash", "A", null);
    // set id via reflection
    try { var f = com.example.access_management.common.entity.BaseEntity.class.getDeclaredField("id"); f.setAccessible(true); f.set(user, 1L); } catch (Exception ignored) {}
    when(ur.findByEmail("a@test.com")).thenReturn(Optional.of(user));
    var sess = com.example.access_management.auth.entity.UserSession.builder().user(user).ipAddress("1.1.1.1").userAgent("OldUA/1.0").lastActive(Instant.now()).isActive(true).build();
    when(usr.findTopByUserIdAndIsActiveTrueOrderByLastActiveDesc(1L)).thenReturn(Optional.of(sess));

    var svc = service(lar, usr, ur, clockAtHour(10));
    var r = svc.calculateRisk("a@test.com", "2.2.2.2", "NewUA/2.0");
    assertThat(r.score()).isEqualTo(70); // 40 ip +30 ua
    assertThat(r.level()).isEqualTo("MEDIUM");
    assertThat(r.suspicious()).isTrue();
  }

  @Test
  void outsideHours_adds10() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc(anyString())).thenReturn(Optional.empty());
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(anyString(), any())).thenReturn(0L);
    when(ur.findByEmail(anyString())).thenReturn(Optional.empty());

    var svcNight = service(lar, usr, ur, clockAtHour(3));
    var rNight = svcNight.calculateRisk("b@test.com", "1.1.1.1", "Mozilla/5.0");
    assertThat(rNight.score()).isEqualTo(10);
    assertThat(rNight.reasons()).anyMatch(s -> s.contains("outside normal hours"));

    var svcDay = service(lar, usr, ur, clockAtHour(10));
    var rDay = svcDay.calculateRisk("b@test.com", "1.1.1.1", "Mozilla/5.0");
    assertThat(rDay.score()).isEqualTo(0);
  }

  @Test
  void failedAttempts_adds20_andSuspicious() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.empty());
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(eq("a@test.com"), any())).thenReturn(5L);
    when(ur.findByEmail(anyString())).thenReturn(Optional.empty());

    var svc = service(lar, usr, ur, clockAtHour(10));
    var r = svc.calculateRisk("a@test.com", "1.1.1.1", "Mozilla/5.0");
    assertThat(r.score()).isEqualTo(20);
    assertThat(r.level()).isEqualTo("LOW");

    // combined with ip change -> 60 medium
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.of(attempt("1.1.1.1")));
    var r2 = svc.calculateRisk("a@test.com", "9.9.9.9", "Mozilla/5.0");
    assertThat(r2.score()).isEqualTo(60);
    assertThat(r2.suspicious()).isTrue();
  }

  @Test
  void level_high_over70() {
    var lar = mock(LoginAttemptRepository.class);
    var usr = mock(UserSessionRepository.class);
    var ur = mock(UserRepository.class);
    when(lar.findTopByEmailAndSuccessTrueOrderByAttemptedAtDesc("a@test.com")).thenReturn(Optional.of(attempt("1.1.1.1")));
    when(lar.countByEmailAndSuccessFalseAndAttemptedAtAfter(anyString(), any())).thenReturn(5L);
    var user = com.example.access_management.user.entity.User.create("a@test.com", "hash", "A", null);
    try { var f = com.example.access_management.common.entity.BaseEntity.class.getDeclaredField("id"); f.setAccessible(true); f.set(user, 1L); } catch (Exception ignored) {}
    when(ur.findByEmail("a@test.com")).thenReturn(Optional.of(user));
    var sess = com.example.access_management.auth.entity.UserSession.builder().user(user).ipAddress("1.1.1.1").userAgent("OldUA/1.0").lastActive(Instant.now()).isActive(true).build();
    when(usr.findTopByUserIdAndIsActiveTrueOrderByLastActiveDesc(1L)).thenReturn(Optional.of(sess));

    var svc = service(lar, usr, ur, clockAtHour(3)); // 40+30+20+10=100
    var r = svc.calculateRisk("a@test.com", "9.9.9.9", "NewUA/2.0");
    assertThat(r.score()).isEqualTo(100);
    assertThat(r.level()).isEqualTo("HIGH");
    assertThat(r.suspicious()).isTrue();
  }
}
