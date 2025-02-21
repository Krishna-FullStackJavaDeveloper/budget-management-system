package com.auth.jwt;

import com.auth.serviceImpl.RefreshTokenService;
import com.auth.serviceImpl.UserDetailsServiceImpl;
import io.jsonwebtoken.JwtException;
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

        String jwt = parseJwt(request);
        if (jwt == null) {
            log.warn("JWT is null, proceeding with request.");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (jwtUtils.validateJwtToken(jwt)) {
                authenticateUser(jwt, request);
            } else {
                handleRefreshToken(request, response);
            }
        } catch (JwtException e) {
            log.error("JWT processing error: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error in authentication filter: ", e);
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateUser(String jwt, HttpServletRequest request) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("User authenticated successfully: {}", username);
    }

    private void handleRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = request.getHeader("Refresh-Token");
        if (StringUtils.hasText(refreshToken) && refreshTokenService.validateRefreshToken(refreshToken)) {
            String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
            log.info("Refreshing token for user: {}", username);

            String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
            response.setHeader("Authorization", "Bearer " + newAccessToken);

            authenticateUser(newAccessToken, request);
        } else {
            log.warn("Invalid or missing refresh token.");
        }
    }

    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        return (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) ? headerAuth.substring(7) : null;
    }





}
