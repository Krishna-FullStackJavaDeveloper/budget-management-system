package com.auth.controller;

import com.auth.entity.ERole;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.jwt.AuthTokenFilter;
import com.auth.jwt.JwtUtils;
import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.response.ApiResponse;
import com.auth.payload.response.JwtResponse;
import com.auth.payload.response.MessageResponse;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.email.EmailService;
import com.auth.serviceImpl.RefreshTokenService;
import com.auth.serviceImpl.UserDetailsImpl;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtResponse>> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            String accessToken = jwtUtils.generateJwtToken(authentication);
            String refershToken = refreshTokenService.createRefreshToken(userDetails.getUser());
            log.info("Generated refresh token: {}", refershToken);

        // Send login notification email asynchronously (to improve response time)
            CompletableFuture.runAsync(() -> emailService.sendLoginNotification(userDetails.getEmail()));
            log.info("User {} logged in successfully", loginRequest.getUsername());
            return ResponseEntity.ok(new ApiResponse<>("Login successful",
                    new JwtResponse(accessToken,
                            userDetails.getId(),
                            userDetails.getUsername(),
                            userDetails.getEmail(),
                            roles,
                            refershToken),
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
                    encoder.encode(signUpRequest.getPassword()));

            Set<String> strRoles = signUpRequest.getRole();
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
