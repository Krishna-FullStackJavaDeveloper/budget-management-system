package com.auth.email;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.ZonedDateTime;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.HashMap;
import java.util.Map;
import java.util.Locale;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender emailSender;
    private final EmailTemplateService emailTemplateService;

    @Value("${spring.mail.username}") // Fetch sender email from properties
    private String senderEmail;

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    public void sendLoginNotification(String recipientEmail,  String userName, String action) {

        executorService.submit(() -> {
            SimpleMailMessage message = new SimpleMailMessage();

            // Load templates lazily
            emailTemplateService.loadTemplates("notification-email-templates.properties");
            // Get subject
            String subject = emailTemplateService.getSubject("email." +action);

            // Format the date and time
            ZonedDateTime now = ZonedDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy, EEEE | h:mm a", Locale.ENGLISH);
            String formattedTime = "Today (" + now.format(formatter) + ")";

            // Prepare dynamic placeholders
            Map<String, String> placeholders = new HashMap<>();
            placeholders.put("name", userName);
            placeholders.put("formatted_time", formattedTime);

            // Get formatted body with dynamic values
            String body = emailTemplateService.getFormattedBody("email." +action, placeholders);

            // Set email details
            message.setFrom("Art Asylum <" + senderEmail + ">");
            message.setReplyTo("no-reply@gmail.com");
            message.setTo(recipientEmail);
            message.setSubject(subject);
            message.setText(body);

            try {
                // Send the email
                emailSender.send(message);
                log.info("Notification email sent to {}", recipientEmail);
            } catch (Exception e) {
                log.error("Failed to send notification email to {}: {}", recipientEmail, e.getMessage());
            }
        });
    }

    public void sendOTPNotification(String recipientEmail,  String userName, String action,String otpCode) {

        executorService.submit(() -> {
            SimpleMailMessage message = new SimpleMailMessage();

            // Load templates lazily
            emailTemplateService.loadTemplates("notification-email-templates.properties");
            // Get subject
            String subject = emailTemplateService.getSubject("email." +action);

            // Format the date and time
            ZonedDateTime now = ZonedDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy, EEEE | h:mm a", Locale.ENGLISH);
            String formattedTime = "Today (" + now.format(formatter) + ")";

            // Prepare dynamic placeholders
            Map<String, String> placeholders = new HashMap<>();
            placeholders.put("name", userName);
            placeholders.put("otp", otpCode);

            placeholders.put("formatted_time", formattedTime);

            // Get formatted body with dynamic values
            String body = emailTemplateService.getFormattedBody("email." +action, placeholders);

            // Set email details
            message.setFrom("Art Asylum <" + senderEmail + ">");
            message.setReplyTo("no-reply@gmail.com");
            message.setTo(recipientEmail);
            message.setSubject(subject);
            message.setText(body);

            try {
                // Send the email
                emailSender.send(message);
                log.info("OTP email sent to {}", recipientEmail);
            } catch (Exception e) {
                log.error("Failed to send OTP email to {}: {}", recipientEmail, e.getMessage());
            }
        });
    }

    @PreDestroy
    public void shutdown() {
        executorService.shutdown();
    }
}
