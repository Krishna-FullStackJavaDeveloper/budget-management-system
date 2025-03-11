package com.auth.serviceImpl;

import com.auth.email.EmailService;
import com.auth.entity.Family;
import com.auth.entity.User;
import com.auth.payload.request.SignupRequest;
import com.auth.repository.FamilyRepository;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
@Service
@Slf4j
@RequiredArgsConstructor
public class FamilyService {

    private final FamilyRepository familyRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final UserDetailsServiceImpl userDetailsService;

    @Transactional
    public Family createFamilyByAdmin(User admin, String familyName) throws Exception {
        if (familyName == null || familyName.trim().isEmpty()) {
            throw new RuntimeException("Error: Family name is required.");
        }
        if (familyRepository.existsByFamilyName(familyName)) {
            throw new RuntimeException("Error: Family name already exists.");
        }

        Family family = new Family(familyName);
        family.setModerator(admin);
        family.setUserSize(1); // Initially, 1 (the moderator)
        familyRepository.save(family);

        admin.setFamily(family);
        userRepository.save(admin);  // Link admin as moderator of the family
        return family;
    }

    public User createFamilyUser(SignupRequest signUpRequest) throws Exception {
        if (signUpRequest.getFamilyName() == null || signUpRequest.getFamilyName().trim().isEmpty()) {
            throw new RuntimeException("Error: Family name is required.");
        }

        Optional<User> familyAdmin = userDetailsService.getModeratorFromRequest(signUpRequest.getFamilyName());
        if (familyAdmin.isEmpty()) {
            throw new RuntimeException("Error: Family Admin not found for the family.");
        }

        Optional<Family> familyOptional = familyRepository.findByFamilyName(signUpRequest.getFamilyName());
        if (familyOptional.isEmpty()) {
            throw new RuntimeException("Error: Family not found.");
        }

        Family family = familyOptional.get();  //  Extract family safely before using it

        Hibernate.initialize(family.getUsers());
        if (family.getUserSize() >= 6) {
            throw new RuntimeException("Error: Family user size limit (6) reached.");
        }

        User user = userDetailsService.createNewUser(signUpRequest);
        user.setFamily(family);  // Assign user to family

//        family.addUser(user);  // Add user to family list
        family.setUserSize(family.getUserSize() + 1);

        familyRepository.save(family);
//        userRepository.save(user);  // Ensure the new user is saved
        sendNotificationEmail(familyAdmin.get());
        return user;
    }

    @Async
    private void sendNotificationEmail(User moderator) {
        // Send email to the moderator
        emailService.sendLoginNotification(moderator.getEmail(), moderator.getFullName(), "userCreated");
    }

}
