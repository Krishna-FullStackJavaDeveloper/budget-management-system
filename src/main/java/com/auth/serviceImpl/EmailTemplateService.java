package com.auth.serviceImpl;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.util.Properties;

@Service
@RequiredArgsConstructor
public class EmailTemplateService {

    private final Properties emailTemplates = new Properties();

    public void loadTemplates(String fileName) {
        try {
            Resource resource = new ClassPathResource(fileName);
            emailTemplates.load(Files.newInputStream(resource.getFile().toPath()));
        } catch (IOException e) {
            throw new RuntimeException("Failed to load email templates from " + fileName, e);
        }
    }

    public String getSubject(String key) {
        return emailTemplates.getProperty(key + ".subject", "No Subject");
    }

    public String getBody(String key) {
        return emailTemplates.getProperty(key + ".body", "No Content");
    }

}
