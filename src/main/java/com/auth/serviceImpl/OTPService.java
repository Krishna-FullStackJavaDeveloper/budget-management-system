package com.auth.serviceImpl;

import com.auth.eNum.OTPStatus;
import com.auth.email.EmailService;
import com.auth.entity.OTP;
import com.auth.entity.User;
import com.auth.globalException.OTPGenerationException;
import com.auth.repository.OTPRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;

import static java.lang.String.valueOf;

@Service
@RequiredArgsConstructor
@Slf4j
public class OTPService {

    private final OTPRepository otpRepository;
    private final EmailService emailService;
    private static final int OTP_EXPIRY_MINUTES = 5;
    private static final int OTP_REUSE_THRESHOLD_SECONDS = 60;


    //generate OTP
    @Transactional
    public OTP generateOTP(User user) {
        try {
            Optional<OTP> latestOtpOpt = otpRepository.findByUserOrderByExpiryTimeDesc(user, OTPStatus.ACTIVE);
            if (latestOtpOpt.isPresent()) {
                OTP latestOtp = latestOtpOpt.get();
                if (latestOtp.getExpirytime().isAfter(LocalDateTime.now().minusSeconds(OTP_REUSE_THRESHOLD_SECONDS))) {
                    log.info("Reusing OTP for user: {}", user.getUsername());

                    // Send email with the old OTP
                    CompletableFuture.runAsync(() -> {
                        try {
                            emailService.sendOTPNotification(user.getEmail(), user.getUsername(), "otp", latestOtp.getOtp());
                        } catch (Exception e) {
                            log.error("Failed to send OTP email for user: {}", user.getUsername(), e);
                        }
                    });
                    return latestOtp;
                }
                log.info("Expiring old OTP for user: {}", user.getUsername());
                latestOtp.setStatus(OTPStatus.EXPIRED);
                otpRepository.save(latestOtp);
            }

// Generate a new OTP if no valid one exists or the old one expired
            String otpCode = generateRandomOTP();
            OTP newOtp = OTP.builder()
                    .user(user)
                    .otp(otpCode)
                    .expirytime(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES))
                    .status(OTPStatus.ACTIVE)
                    .build();

            OTP savedOtp = otpRepository.save(newOtp);
            log.info("New OTP generated for user: {}", user.getUsername());

            // Send the new OTP via email asynchronously
            CompletableFuture.runAsync(() -> {
                try {
                    emailService.sendOTPNotification(user.getEmail(), user.getUsername(), "otp", otpCode);
                } catch (Exception e) {
                    log.error("Failed to send OTP email for user: {}", user.getUsername(), e);
                }
            });

            return savedOtp;
        } catch (Exception e) {
            log.error("Error while generating OTP for user: {}", user.getUsername(), e);
            throw new OTPGenerationException("Failed to generate OTP", e);
        }
    }

    private String generateRandomOTP() {
        SecureRandom secureRandom = new SecureRandom();
        String otpCode = String.valueOf(100000 + secureRandom.nextInt(900000));// Generates 6-digit OTP
        return otpCode;
    }

    // Verify OTP
    @Transactional
    public boolean verifyOTP(User user, String inputOtp) {
        try {
            Optional<OTP> latestOtpOpt = otpRepository.findByUserOrderByExpiryTimeDesc(user, OTPStatus.ACTIVE);

            if (latestOtpOpt.isEmpty()) {
                log.warn("No active OTP found for user: {}", user.getUsername());
                return false;
            }

            OTP latestOtp = latestOtpOpt.get();

            if (latestOtp.getExpirytime().isBefore(LocalDateTime.now())) {
                log.warn("OTP expired for user: {}", user.getUsername());
                latestOtp.setStatus(OTPStatus.EXPIRED);
                otpRepository.save(latestOtp);
                return false;
            }

            if (!latestOtp.getOtp().equals(inputOtp)) {
                log.warn("Invalid OTP entered for user: {}", user.getUsername());
                return false;
            }

            // OTP is valid - Mark as used
            latestOtp.setStatus(OTPStatus.USED);
            otpRepository.save(latestOtp);
            log.info("OTP verified successfully for user: {}", user.getUsername());
            return true;
        } catch (Exception e) {
            log.error("Error occurred while verifying OTP for user: {}", user.getUsername(), e);
            return false;
        }
    }
}
