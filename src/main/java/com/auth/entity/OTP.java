package com.auth.entity;

import com.auth.eNum.OTPStatus;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "otp")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OTP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)  // Lazy loading for user relation
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user; // Links OTP to a user

    @NotBlank
    private String otp;

    @Column(nullable = false)
    private LocalDateTime expirytime; // OTP expiration time

    @Enumerated(EnumType.STRING)
    private OTPStatus status; // ACTIVE, USED, EXPIRED

}
