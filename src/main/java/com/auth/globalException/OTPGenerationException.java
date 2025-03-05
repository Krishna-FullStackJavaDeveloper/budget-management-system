package com.auth.globalException;

public class OTPGenerationException extends RuntimeException {
    public OTPGenerationException(String message) {
        super(message);
    }

  public OTPGenerationException(String message, Throwable cause) {
    super(message, cause);
  }
}
