package com.auth.serviceImpl;

import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
public class EmailTemplateService {

    // Properties to hold the templates
    private final Map<String, String> cachedSubjects = new HashMap<>();
    private final Map<String, String> cachedBodies = new HashMap<>();
    private boolean templatesLoaded = false;

    public void loadTemplates(String fileName) {

            if (!templatesLoaded) {
                Properties emailTemplates = new Properties();

                try {
                    Resource resource = new ClassPathResource(fileName);
                    emailTemplates.load(Files.newInputStream(resource.getFile().toPath()));

                    // Cache subjects and bodies
                    for (String key : emailTemplates.stringPropertyNames()) {
                        if (key.endsWith(".subject")) {
                            cachedSubjects.put(key.replace(".subject", ""), emailTemplates.getProperty(key));
                        } else if (key.endsWith(".body")) {
                            cachedBodies.put(key.replace(".body", ""), emailTemplates.getProperty(key));
                        }
                    }

                    templatesLoaded = true; // Mark templates as loaded

                } catch (IOException e) {
                    throw new RuntimeException("Failed to load email templates from " + fileName, e);
                }
            }
    }

    public String getSubject(String key) {
        loadTemplates("email-templates.properties"); // Call to load templates if not already loaded
        return cachedSubjects.getOrDefault(key, "No Subject"); // Use cached subjects
    }

    public String getBody(String key) {
        loadTemplates("email-templates.properties"); // Call to load templates if not already loaded
        return cachedBodies.getOrDefault(key, "No Content"); // Use cached bodies
    }

}
