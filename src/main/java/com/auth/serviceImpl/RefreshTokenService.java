package com.auth.serviceImpl;

import com.auth.entity.ERole;
import com.auth.entity.RefreshToken;
import com.auth.entity.User;
import com.auth.jwt.JwtUtils;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

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
        // Save the refresh token to the database
        RefreshToken tokenEntity = new RefreshToken();
        tokenEntity.setUser(user);
        tokenEntity.setToken(refreshToken);
        tokenEntity.setExpiryDate(Instant.now().plusMillis(86400000)); // Set expiration (e.g., 1 day)

        refreshTokenRepository.save(tokenEntity); // Save to the database

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
