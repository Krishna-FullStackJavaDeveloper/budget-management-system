package com.auth.controller;

import com.auth.entity.User;
import com.auth.payload.response.ApiResponse;
import com.auth.payload.response.GetUserByIdResponse;
import com.auth.serviceImpl.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/user/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public ResponseEntity<ApiResponse<GetUserByIdResponse>> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        GetUserByIdResponse responsePayload = new GetUserByIdResponse(user);
        ApiResponse<GetUserByIdResponse> response = new ApiResponse<>(
                "User retrieved successfully",
                responsePayload,
                HttpStatus.OK.value()
        );
        return ResponseEntity.ok(response);
    }

}
