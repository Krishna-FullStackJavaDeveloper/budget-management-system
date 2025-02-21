package com.auth.repository;

import com.auth.entity.RefreshToken;
import com.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUser(User user);

    // Method to find all refresh tokens that have expired
    List<RefreshToken> findByExpiryDateBefore(Instant expiryDate);

}
