package com.auth.serviceImpl;

import com.auth.eNum.AccountStatus;
import com.auth.eNum.ERole;
import com.auth.entity.Family;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.payload.request.SignupRequest;
import com.auth.repository.FamilyRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final FamilyRepository familyRepository;

    // Cache to hold UserDetails
    private final Map<String, UserDetails> userDetailsCache = new ConcurrentHashMap<>();

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Check the cache first
        if (userDetailsCache.containsKey(username)) {
            log.info("User found in cache: {}", username);
            return userDetailsCache.get(username);
        }

        // Fetch user from the database
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    log.error("User not found with username: {}", username);
                    return new UsernameNotFoundException("User Not Found with username: " + username);
                });

        // Build UserDetails and cache it
        UserDetails userDetails = UserDetailsImpl.build(user);
        userDetailsCache.put(username, userDetails);
        log.info("User loaded from database: {}", username);

        return userDetails;
    }

    public List<String> getAllAdminEmails() {
        return userRepository.findAdmins()
                .stream()
                .map(User::getEmail)
                .collect(Collectors.toList());
    }

    // Method to get the moderator from the request (if provided)
    public Optional<User> getModeratorFromRequest(String familyName) {

        Optional<Family> family = familyRepository.findByFamilyName(familyName);
        if (family.isEmpty() || family.get().getId() == null) {
            return Optional.empty();
        }else {
            Optional<User> userAdmin = userRepository.findModeratorByFamilyId(family.get().getId());
            userAdmin.ifPresent(user -> System.out.println("Moderator: " + user.getUsername()));
            return userAdmin;
        }
    }



    public Set<Role> getRolesFromRequest(Set<String> strRoles) {
        Set<Role> roles = new HashSet<>();
        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found.")));
            return roles;
        }
        for (String role : strRoles) {
            ERole eRole = switch (role.toLowerCase()) {
                case "admin" -> ERole.ROLE_ADMIN;
                case "mod" -> ERole.ROLE_MODERATOR;
                case "user" -> ERole.ROLE_USER;
                default -> throw new RuntimeException("Error: Invalid role specified!");
            };
            roles.add(roleRepository.findByName(eRole)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found.")));
        }
        return roles;
    }

    public User createNewUser(SignupRequest signUpRequest) {
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getFullName(),
                signUpRequest.getPhoneNumber());

        user.setAccountStatus(AccountStatus.valueOf(signUpRequest.getAccountStatus()));
        user.setTwoFactorEnabled(signUpRequest.isTwoFactorEnabled());
        user.setProfilePic(signUpRequest.getProfilePic());

        Set<Role> roles = getRolesFromRequest(signUpRequest.getRole());
        user.setRoles(roles);
//        userRepository.save(user);
        // Save user to repository or return user to controller
        return user;
    }

}
