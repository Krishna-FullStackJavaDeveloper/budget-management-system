package com.auth.jwt;

import com.auth.serviceImpl.RefreshTokenService;
import com.auth.serviceImpl.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter  {

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;
    private final RefreshTokenService refreshTokenService;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.debug("Processing request: " + request.getRequestURI());

        try {
            String jwt = parseJwt(request);
            log.debug("JWT from request: {}", jwt);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("User authenticated: {}", username);

            } else if (jwt != null && !jwtUtils.validateJwtToken(jwt)) {
                log.warn("JWT is invalid. Checking for refresh token...");

                // Handle refresh token logic
                String refreshToken = request.getHeader("Refresh-Token");
                if (refreshToken != null && refreshTokenService.validateRefreshToken(refreshToken)) {
                    // Get the username from the refresh token
                    String usernameFromRefreshToken = jwtUtils.getUserNameFromJwtToken(refreshToken);
                    log.debug("Username extracted from refresh token: {}", usernameFromRefreshToken);

                    // Generate a new access token using the username from the refresh token
                    String newAccessToken = jwtUtils.generateJwtTokenFromUsername(usernameFromRefreshToken);
                    response.setHeader("Authorization", "Bearer " + newAccessToken);
                    log.info("Access token refreshed for user: {}", usernameFromRefreshToken);

                    // Optionally, you can set the authentication again with the refreshed token
                    UserDetails newUserDetails = userDetailsService.loadUserByUsername(usernameFromRefreshToken);
                    UsernamePasswordAuthenticationToken newAuthentication =
                            new UsernamePasswordAuthenticationToken(
                                    newUserDetails,
                                    null,
                                    newUserDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(newAuthentication);
                } else {
                    log.warn("Refresh token is invalid or missing");
                }
            } else {
                log.warn("JWT is null");
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
