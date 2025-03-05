package com.auth.repository;

import com.auth.eNum.OTPStatus;
import com.auth.entity.OTP;
import com.auth.entity.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.ZonedDateTime;
import java.util.Optional;

@Repository
public interface OTPRepository extends JpaRepository<OTP, Long> {

    @Query("SELECT COUNT(o) > 0 FROM OTP o WHERE o.user = :user")
    Boolean existsByUser(@Param("user") User user);

    @Query("SELECT o FROM OTP o WHERE o.user = :user AND o.status = :status ORDER BY o.expirytime DESC")
    Optional<OTP> findByUserOrderByExpiryTimeDesc(@Param("user") User user, @Param("status") OTPStatus opOtpStatus);

    @Modifying
    @Query("UPDATE OTP o SET o.status = 'EXPIRED' WHERE o.user = ?1 AND o.status = 'ACTIVE'")
    void expireOldOTPs(@Param("user") User user);

}
