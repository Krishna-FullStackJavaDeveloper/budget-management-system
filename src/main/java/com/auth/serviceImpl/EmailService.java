package com.auth.serviceImpl;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender emailSender;
    private final EmailTemplateService emailTemplateService;

    @Value("${spring.mail.username}") // Fetch sender email from properties
    private String senderEmail;

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();

    public void sendLoginNotification(String recipientEmail) {

        executorService.submit(() -> {
            SimpleMailMessage message = new SimpleMailMessage();

            // Load templates lazily
            emailTemplateService.loadTemplates("notification-email-templates.properties");

            // Get subject and body from the login template
            String subject = emailTemplateService.getSubject("email.login");
            String body = emailTemplateService.getBody("email.login");

            // Set email details
            message.setFrom(senderEmail);
            message.setTo(recipientEmail);
            message.setSubject(subject);
            message.setText(body);

            try {
                // Send the email
                emailSender.send(message);
                log.info("Login notification email sent to {}", recipientEmail);
            } catch (Exception e) {
                log.error("Failed to send login notification email to {}: {}", recipientEmail, e.getMessage());
            }
        });
    }

    @PreDestroy
    public void shutdown() {
        executorService.shutdown();
    }
}
