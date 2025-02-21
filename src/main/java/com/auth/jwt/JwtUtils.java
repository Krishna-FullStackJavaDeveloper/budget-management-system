package com.auth.jwt;

import com.auth.serviceImpl.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtUtils {

    @Value("${security.jwt.secret-key}")
    private String jwtSecret;

    @Value("${security.jwt.access-token.expiration-time}")
    private int accessTokenExpirationMs;

    @Value("${security.jwt.refresh-token.extended-expiration-time}")
    private int refreshTokenExpirationMs;

    private Key cachedKey;

    //    Generates an access token for an authenticated user.
    public String generateJwtToken(Authentication authentication) {
        return generateToken(((UserDetailsImpl) authentication.getPrincipal()).getUsername(), accessTokenExpirationMs);
    }

    //     Generates a refresh token for an authenticated user.
    public String generateRefreshToken(Authentication authentication) {
        return generateToken(((UserDetailsImpl) authentication.getPrincipal()).getUsername(), refreshTokenExpirationMs);
    }

    //    Generates a new access token from a username
    public String generateJwtTokenFromUsername(String username) {
        return generateToken(username, accessTokenExpirationMs);
    }

    //    Extracts username from a JWT token.
    public String getUserNameFromJwtToken(String token) {
        return parseTokenClaims(token).getSubject();
    }

    // Validates a JWT token.

    public boolean validateJwtToken(String authToken) {
        try {
            parseTokenClaims(authToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    // ============================= PRIVATE HELPER METHODS =============================

    //    Generates a JWT token with a specified expiration time.
    private String generateToken(String username, int expirationMs) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expirationMs))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //    Returns the signing key, caching it to avoid redundant decoding.
    private Key getSigningKey() {
        if (cachedKey == null) {
            synchronized (this) { // Ensures thread safety
                if (cachedKey == null) {
                    cachedKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
                }
            }
        }
        return cachedKey;
    }

    //     Parses and retrieves claims from a JWT token.
    private Claims parseTokenClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}
