package com.auth.payload.request;

import com.auth.entity.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.util.Set;

@Getter
@Setter
@RequiredArgsConstructor
public class SignupRequest {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank(message = "Email is required")
    @Size(max = 50)
    @Email(message = "Email should be valid")
    private String email;

    // The role field can be null or empty, which is handled in controller
    private Set<String> role;

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 40)
    private String password;

    @NotBlank(message = "Full name is required")
    @Size(max = 50)
    private String fullName;

    @NotBlank(message = "Phone number is required")
    @Size(max = 15, message = "Phone number should not exceed 15 characters")
    private String phoneNumber;

    private String profilePic; // Store Base64 string instead of MultipartFile

    private String accountStatus = "ACTIVE";  // Default to ACTIVE status, can be "ACTIVE" or "INACTIVE"

    private boolean twoFactorEnabled = false;  // Default to false for 2FA
}
