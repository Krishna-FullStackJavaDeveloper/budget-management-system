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

    //generate OTP
    @Transactional
    public OTP generateOTP(User user) {
        try {
            //Expire previous OTPs.
            if (otpRepository.existsByUser(user)){
                log.info("Existing OTPs found for user: {}. Expiring old OTPs.", user.getUsername());

                otpRepository.expireOldOTPs(user);
            }

            //Generate new OTP.
            String otpCode = generateRandomOTP();
            OTP newOtp = new OTP();
            newOtp.setUser(user);
            newOtp.setOtp(otpCode);
            newOtp.setExpirytime(LocalDateTime.now().plusMinutes(15)); // 5 minute expiry
            newOtp.setStatus(OTPStatus.ACTIVE);

            log.info("Generate new OTP for user: {}", user.getUsername());
            OTP savedotp = otpRepository.save(newOtp);

            log.info("Current timestamp: {}", LocalDateTime.now());
            log.info("Expiry time for OTP: {}", savedotp.getExpirytime());


            // Send OTP via email asynchronously.
            CompletableFuture.runAsync(() -> {
                try {
                    emailService.sendOTPNotification(user.getEmail(), user.getUsername(), "otp", otpCode);
                } catch (Exception e) {
                    log.error("Failed to send OTP email for user: {}", user.getUsername(), e);
                }
            });

            return savedotp;
        } catch (Exception e) {
            log.error("Error occurred while generating OTP for user: {}", user.getUsername(), e);
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
