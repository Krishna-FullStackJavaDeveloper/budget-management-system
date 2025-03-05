package com.auth.controller;

import com.auth.eNum.AccountStatus;
import com.auth.eNum.ERole;
import com.auth.entity.OTP;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.jwt.AuthTokenFilter;
import com.auth.jwt.JwtUtils;
import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.OTPVerificationRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.response.ApiResponse;
import com.auth.payload.response.JwtResponse;
import com.auth.repository.OTPRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.email.EmailService;
import com.auth.security.OtpAuthenticationToken;
import com.auth.serviceImpl.OTPService;
import com.auth.serviceImpl.RefreshTokenService;
import com.auth.serviceImpl.UserDetailsImpl;
import com.auth.serviceImpl.UserDetailsServiceImpl;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final EmailService emailService;
    private final AuthTokenFilter authTokenFilter;
    private final OTPService otpService;
    private final UserDetailsServiceImpl userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtResponse>> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        log.debug("User login attempt for username: {}", loginRequest.getUsername());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (user.isTwoFactorEnabled()) {
            // If 2FA is enabled, generate and send OTP
            otpService.generateOTP(user); //otp is generated and saved.
            return ResponseEntity.ok(new ApiResponse<>("2FA OTP sent to your email", null, HttpStatus.ACCEPTED.value()));
        }

        List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            String accessToken = jwtUtils.generateJwtToken(authentication);
            String refreshToken = refreshTokenService.createRefreshToken(userDetails.getUser());
            log.info("Generated refresh token: {}", refreshToken);

        // Send login notification email asynchronously (to improve response time)
            CompletableFuture.runAsync(() -> emailService.sendLoginNotification(userDetails.getEmail(), userDetails.getUsername(),"login"));
            log.info("User {} logged in successfully", loginRequest.getUsername());
            return ResponseEntity.ok(new ApiResponse<>("Login successful",
                    new JwtResponse(accessToken,
                            userDetails.getId(),
                            userDetails.getUsername(),
                            userDetails.getEmail(),
                            roles,
                            refreshToken),
                    HttpStatus.OK.value()
            ));// Include the refresh token in the response

    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<JwtResponse>> verifyOtpAndLogin(
            @Valid @RequestBody OTPVerificationRequest otpRequest) {

        log.debug("Verifying user OTP attempt for username: {}", otpRequest.getUsername());

        User user = userRepository.findByUsername(otpRequest.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        boolean isOtpValid = otpService.verifyOTP(user, otpRequest.getOtp());

        if (!isOtpValid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid or expired OTP", null, HttpStatus.UNAUTHORIZED.value()));
        }

        // Load user details
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(otpRequest.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Generate JWT tokens using JwtUtils
        String accessToken = jwtUtils.generateJwtToken(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
        String refreshToken = jwtUtils.generateRefreshToken(new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
        log.info("Generated refresh token after OTP Creation: {}", refreshToken);

        // Send login notification email asynchronously (to improve response time)
        CompletableFuture.runAsync(() -> emailService.sendLoginNotification(userDetails.getEmail(), userDetails.getUsername(),"login"));
        log.info("User {} logged in successfully!", otpRequest.getUsername());
        return ResponseEntity.ok(new ApiResponse<>("Login successful",
                new JwtResponse(accessToken,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles,
                        refreshToken),
                HttpStatus.OK.value()
        ));// Include the refresh token in the response
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<String>> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity
                        .badRequest()
                        .body(new ApiResponse<>("Error: Username is already taken!", null, HttpStatus.BAD_REQUEST.value()));
            }

            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity
                        .badRequest()
                        .body(new ApiResponse<>("Error: Email is already in use!", null, HttpStatus.BAD_REQUEST.value()));
            }
        // Create new user's account
            User user = new User(signUpRequest.getUsername(),
                    signUpRequest.getEmail(),
                    encoder.encode(signUpRequest.getPassword()),
                    signUpRequest.getFullName(),
                    signUpRequest.getPhoneNumber()
                    );
        user.setAccountStatus(AccountStatus.valueOf(signUpRequest.getAccountStatus())); // Set account status
        user.setTwoFactorEnabled(signUpRequest.isTwoFactorEnabled()); // Set 2FA flag
        user.setProfilePic(signUpRequest.getProfilePic());  // Save the Base64 encoded image string in the database

        Set<String> strRoles = signUpRequest.getRole();
        log.info("user{} request Role", strRoles);
        Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    switch (role) {
                        case "admin":
                            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(adminRole);

                            break;
                        case "mod":
                            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(modRole);

                            break;
                        default:
                            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(userRole);
                    }
                });
            }
            user.setRoles(roles);
            userRepository.save(user);
            // Send login notification email asynchronously (to improve response time)
            CompletableFuture.runAsync(() -> emailService.sendLoginNotification(user.getEmail(), user.getFullName(),"register"));
            log.info("Signup message sent successfully", signUpRequest.getUsername() + signUpRequest.getEmail());

        // Return successful response
            ApiResponse<String> response = new ApiResponse<>("User registered successfully!", null, HttpStatus.OK.value());
            return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public  CompletableFuture<ResponseEntity<ApiResponse<String>>> refreshToken(HttpServletRequest request) {
        String refreshToken = authTokenFilter.parseJwt(request);

        if (!refreshTokenService.validateRefreshToken(refreshToken)) {
            throw new JwtException("Invalid refresh token"); // Let GlobalExceptionHandler handle it
        }

        String username = jwtUtils.getUserNameFromJwtToken(refreshToken);

        return CompletableFuture.supplyAsync(() -> userRepository.findByUsername(username))
                .thenApply(userOptional -> {
                    if (userOptional.isEmpty()) {
                        throw new UsernameNotFoundException("User not found"); // Also handled globally
                    }

                    String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
                    return ResponseEntity.ok(
                            new ApiResponse<>("Token refreshed successfully", newAccessToken, HttpStatus.OK.value())
                    );
                });

    }
}
