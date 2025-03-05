package com.auth.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OTPVerificationRequest {

    @NotBlank(message = "Username is required")
    private String username;
//    @NotBlank(message = "Password is required")
//    private String password;
    @NotBlank(message = "OTP is required")
    private String otp;
}
