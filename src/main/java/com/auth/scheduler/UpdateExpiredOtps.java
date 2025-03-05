package com.auth.scheduler;

import com.auth.repository.OTPRepository;
import jakarta.annotation.PreDestroy;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UpdateExpiredOtps {

    private final OTPRepository otpRepository;
    private final ExecutorService executorService = Executors.newFixedThreadPool(2);

    @Scheduled(fixedRate = 60000) //Runs every minute
    public void scheduleOtpExpiry() {
        expireOtpsAsync(); //Calls async method separately
    }

    @Async
    public void expireOtpsAsync() {
        executorService.execute(() -> {
            LocalDateTime now = LocalDateTime.now();

            try {
                log.info("Starting OTP Expiry Check at {}", now);
                int updatedRows = otpRepository.bulkExpireOtps(now);
                log.info("Updated {} OTPs to EXPIRED", updatedRows);
            } catch (Exception e) {
                log.error("Error while expiring OTPs: {}", e.getMessage(), e);
            }
        });
    }

    @PreDestroy
    public void shutdownExecutor() {
        log.info("Shutting down OTP Expiry Scheduler ExecutorService...");
        executorService.shutdown();
    }
}
