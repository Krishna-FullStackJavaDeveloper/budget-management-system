package com.auth.serviceImpl;

import com.auth.entity.RefreshToken;
import com.auth.entity.User;
import com.auth.jwt.JwtUtils;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${security.jwt.refresh-token.expiration-time}")
    private long refreshTokenDurationMs;

    @Value("${security.jwt.refresh-token.extended-expiration-time}")
    private long extendedRefreshTokenDurationMs;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtils jwtUtils;

    // Create a fixed thread pool
    private final ExecutorService executorService = Executors.newFixedThreadPool(10); // Adjust thread count as needed

    // Cached token to avoid repeated database access
    private RefreshToken cachedRefreshToken;

    //Create or refresh the refresh token
    public String createRefreshToken(User user) {

        // Check if a refresh token already exists for the user
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);

        if (existingToken.isPresent()) {
            cachedRefreshToken = existingToken.get();
            // Check if the existing token has expired
            if (cachedRefreshToken.getExpiryDate().isBefore(Instant.now())) {
                // Token has expired, generate a new one
                return generateNewRefreshToken(user);
            } else {
                // Token is still valid, return existing token
                return cachedRefreshToken.getToken();
            }
        } else {
            // No existing token, create a new one
            return generateNewRefreshToken(user);
        }
    }

    private String generateNewRefreshToken(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // Generate the refresh token
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        // Save the refresh token to the database in a separate thread
        executorService.submit(() -> {
            try {
                // Create or update the refresh token entity
                RefreshToken tokenEntity = new RefreshToken();
                tokenEntity.setUser(user);
                tokenEntity.setToken(refreshToken);
                tokenEntity.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs)); // Set new expiration

                refreshTokenRepository.save(tokenEntity); // Save in database
                cachedRefreshToken = tokenEntity; // Cache the newly created token
            } catch (Exception e) {
                log.error("Failed to save refresh token for user {}: {}", user.getUsername(), e.getMessage());
            }
        });

        return refreshToken; // Return the generated refresh token
    }

    public boolean validateRefreshToken(String token) {
        Optional<RefreshToken> storedTokenOpt = refreshTokenRepository.findByToken(token);

        if (storedTokenOpt.isEmpty()) {
            return false; // Token not found
        }

        RefreshToken storedToken = storedTokenOpt.get();

        // Check if the stored token has expired
        if (storedToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(storedToken); // Delete expired token
            return false; // Token expired
        }
        // If token is valid, update the cached token
        cachedRefreshToken = storedToken;

        return true; // Token is valid
    }
    // Shutdown the executor service (consider adding this method in a suitable place in your application lifecycle)
    @PreDestroy
    public void shutdown() {
        executorService.shutdown();
    }
}
