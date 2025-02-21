package com.auth.serviceImpl;

import com.auth.entity.RefreshToken;
import com.auth.entity.User;
import com.auth.jwt.JwtUtils;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${security.jwt.refresh-token.expiration-time}")
    private long refreshTokenDurationMs;

    @Value("${security.jwt.refresh-token.extended-expiration-time}")
    private long extendedRefreshTokenDurationMs;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtils jwtUtils;

    //create refresh token
    public String createRefreshToken(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // Generate the refresh token
        String refreshToken = jwtUtils.generateRefreshToken(authentication);

        // Check if a refresh token already exists for the user
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);

        // Save the refresh token to the database
        RefreshToken tokenEntity;
        if (existingToken.isPresent()) {
            // Update the existing token
            tokenEntity = existingToken.get();
            tokenEntity.setToken(refreshToken);
            tokenEntity.setExpiryDate(Instant.now().plusMillis(86400000)); // Update expiration
        } else {
            // Create a new token entry
            tokenEntity = new RefreshToken();
            tokenEntity.setUser(user);
            tokenEntity.setToken(refreshToken);
            tokenEntity.setExpiryDate(Instant.now().plusMillis(86400000)); // Set expiration (e.g., 1 day)
        }

        refreshTokenRepository.save(tokenEntity); // Save/Update in database

        return refreshToken; // Return the generated refresh token
    }

    public boolean validateRefreshToken(String token) {
        Optional<RefreshToken> storedToken = refreshTokenRepository.findByToken(token);

        if (storedToken.isEmpty()) {
            return false; // Token not found
        }

        if (storedToken.get().getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(storedToken.get()); // Delete expired token
            return false; // Token expired
        }

        return true; // Token is valid
    }
}
