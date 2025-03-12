package com.auth.payload.response;

import com.auth.eNum.AccountStatus;
import com.auth.entity.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;
import com.auth.globalUtils.DateFormatUtil;

@Getter
@Setter
public class GetUserByIdResponse {
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String phoneNumber;
    private String profilePic;
    private AccountStatus accountStatus;
    private String createdAt;
    private String updatedAt;
    private String lastLogin;
    private boolean twoFactorEnabled;
    private Set<String> roles;
//    private String familyName;

    public GetUserByIdResponse(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.fullName = user.getFullName();
        this.phoneNumber = user.getPhoneNumber();
        this.profilePic = user.getProfilePic();
        this.accountStatus = user.getAccountStatus();
        // Format dates using DateFormatUtil
        this.createdAt = DateFormatUtil.formatDate(user.getCreatedAt());
        this.updatedAt = DateFormatUtil.formatDate(user.getUpdatedAt());
        this.lastLogin = DateFormatUtil.formatDate(user.getLastLogin());

        this.twoFactorEnabled = user.isTwoFactorEnabled();
        this.roles = user.getRoles().stream().map(role -> role.getName().name()).collect(Collectors.toSet());
//        this.familyName = user.getFamily() != null ? user.getFamily().getFamilyName() : null;
    }
}
