package com.auth.serviceImpl;

import com.auth.entity.User;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

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
}
