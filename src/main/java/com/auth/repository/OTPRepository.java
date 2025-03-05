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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface OTPRepository extends JpaRepository<OTP, Long> {

    @Query("SELECT COUNT(o) > 0 FROM OTP o WHERE o.user = ?1")
    Boolean existsByUser(@Param("user") User user);

    @Query("SELECT o FROM OTP o WHERE o.user = ?1 AND o.status = ?2 ORDER BY o.expirytime DESC")
    Optional<OTP> findByUserOrderByExpiryTimeDesc(@Param("user") User user, @Param("status") OTPStatus opOtpStatus);

    @Modifying
    @Query("UPDATE OTP o SET o.status = 'EXPIRED' WHERE o.user = ?1 AND o.expirytime < CURRENT_TIMESTAMP AND o.status = 'ACTIVE'")
    void expireOldOTPs(@Param("user") User user);

    @Modifying
    @Transactional
    @Query("UPDATE OTP o SET o.status = 'EXPIRED' WHERE o.status IN ('ACTIVE', 'USED') AND o.expirytime < :currentTime")
    int bulkExpireOtps(LocalDateTime currentTime);

}
