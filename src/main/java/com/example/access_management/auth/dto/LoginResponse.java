package com.example.access_management.auth.dto;

public record LoginResponse(String accessToken, String refreshToken, long expiresIn, String tokenType) {}
