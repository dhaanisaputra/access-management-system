package com.example.access_management.common.exception;

public class AccountLockedException extends RuntimeException {
  public AccountLockedException(String message) {
    super(message);
  }
}
