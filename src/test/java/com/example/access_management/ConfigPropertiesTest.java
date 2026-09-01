package com.example.access_management;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import static org.assertj.core.api.Assertions.assertThat;
@SpringBootTest
class ConfigPropertiesTest {
  @Value("${jwt.secret}") String secret;
  @Value("${jwt.access-expiration}") long accessExp;
  @Test void jwtPropsLoaded() {
    assertThat(secret).isNotBlank();
    assertThat(accessExp).isEqualTo(900000L);
  }
}
