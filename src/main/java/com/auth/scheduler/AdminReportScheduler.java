package com.auth.scheduler;

import com.auth.email.EmailService;
import com.auth.entity.User;
import com.auth.globalException.ReportGenerationException;
import com.auth.serviceImpl.UserDetailsImpl;
import com.auth.serviceImpl.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminReportScheduler {
    private final UserDetailsServiceImpl userDetails;  // Fetch users based on roles
    private final EmailService emailService; // Email sending logic
    private final ExecutorService executorService = Executors.newFixedThreadPool(5); // Thread pool for parallel execution

    @Scheduled(cron = "0 0 9 * * MON") // Every Monday at 9:00 AM
    public void sendWeeklyAdminReports() {
        try {
            List<String> adminEmails = userDetails.getAllAdminEmails();
            if (adminEmails.isEmpty()) {
                log.warn("No admins found for weekly summary report");
                return;
            }

            adminEmails.forEach(adminEmail ->
                    CompletableFuture.runAsync(() -> sendReport(adminEmail), executorService)
            );

        } catch (Exception e) {
            throw new ReportGenerationException("Error generating weekly reports", e);
        }
    }

    private void sendReport(String adminEmail) {
        try {
            emailService.sendLoginNotification(adminEmail, "Admin", "weekly-summary");
            log.info("Weekly summary report sent to {}", adminEmail);
        } catch (Exception e) {
            log.error("Failed to send weekly report to {}: {}", adminEmail, e.getMessage(), e);
        }
    }
}
