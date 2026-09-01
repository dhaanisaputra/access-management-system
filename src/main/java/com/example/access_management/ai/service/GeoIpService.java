package com.example.access_management.ai.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Mock GeoIP. Real GeoLite2 .mmdb can be wired later.
 */
// ponytail: mock GeoIP returns static mapping; replace with MaxMind DatabaseReader when GeoLite2-City.mmdb is available
@Service
@Slf4j
public class GeoIpService {

  public record GeoResult(String country, String city) {}

  public GeoResult lookup(String ip) {
    if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
      return new GeoResult("Unknown", "Unknown");
    }
    String trimmed = ip.split(",")[0].trim();
    if ("127.0.0.1".equals(trimmed) || "0:0:0:0:0:0:0:1".equals(trimmed) || "::1".equals(trimmed) || trimmed.startsWith("192.168.") || trimmed.startsWith("10.")) {
      return new GeoResult("ID", "Jakarta");
    }
    // ponytail: naive stub — all non-local IPs mapped to US/New York until real mmdb is added
    return new GeoResult("US", "New York");
  }
}
