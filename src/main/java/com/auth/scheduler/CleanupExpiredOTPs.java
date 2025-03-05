package com.auth.scheduler;

import com.auth.entity.OTP;
import com.auth.repository.OTPRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class CleanupExpiredOTPs {

    private final OTPRepository otpRepository;
    private final ExecutorService executorService = Executors.newFixedThreadPool(4); // Thread pool for async tasks

    @Scheduled(cron = "0 0 12 * * ?") // Runs every hour
    public void cleanupExpiredOTPs() {
        try{
            log.info("Started cleaning expired OTPs");

            // Using a lazy-loaded stream to process OTPs
            List<OTP> expiredOtps = otpRepository.findAll().stream()
                    .filter(otp -> otp.getExpirytime().isBefore(LocalDateTime.now()))
                    .collect(Collectors.toList());

            // Process in parallel for efficiency
            List<OTP> expiredOtpList = expiredOtps.stream().collect(Collectors.toList());
            if (!expiredOtpList.isEmpty()) {
                executorService.submit(() -> {
                    otpRepository.deleteAll(expiredOtpList);
                    log.info("Deleted {} expired OTPs", expiredOtpList.size());
                });
            } else {
                log.info("No expired OTPs found for cleanup.");
            }
        }catch (Exception e){
            log.error("Error occurred while cleaning expired OTPs", e);
        }
    }
}
