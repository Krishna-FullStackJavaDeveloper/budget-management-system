package com.auth.serviceImpl;

import com.auth.entity.User;
import com.auth.globalException.ResourceNotFoundException;
import com.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional
    public User getUserById(Long id) {
        // Fetching the user using the repository method
        User user = userRepository.getUserByIdWithRoles(id);

        // Handling case if user is not found
        if (user == null) {
            throw new ResourceNotFoundException("User", "id", id);
        }

        return user;
    }
}
