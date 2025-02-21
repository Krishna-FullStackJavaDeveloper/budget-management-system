package com.auth.serviceImpl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender emailSender;
    private final EmailTemplateService emailTemplateService;

    @Value("${spring.mail.username}") // Fetch sender email from properties
    private String senderEmail;

    public EmailService(JavaMailSender emailSender, EmailTemplateService emailTemplateService) {
        this.emailSender = emailSender;
        this.emailTemplateService = emailTemplateService;
        emailTemplateService.loadTemplates("notification-email-templates.properties"); // Load the login templates
    }

    public void sendLoginNotification(String recipientEmail){
        SimpleMailMessage message = new SimpleMailMessage();

        // Get subject and body from the login template
        String subject = emailTemplateService.getSubject("email.login");
        String body = emailTemplateService.getBody("email.login");

        // Set email details
        message.setFrom(senderEmail);
        message.setTo(recipientEmail);
        message.setSubject(subject);
        message.setText(body);

        // Send the email
        emailSender.send(message);
    }
}
