package com.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "family")
@Getter
@Setter
@NoArgsConstructor
public class Family {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 100)
    private String familyName;

    @NotBlank
    @Size(max = 120)
    @Pattern(regexp = "^[a-zA-Z0-9!@#$%^&*(),.?\":{}|<>_+\\-=]*$", message = "Password contains invalid characters.")
    private String passkey;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "moderator_id")
    private User moderator;  // The moderator who created this family

    @OneToMany(mappedBy = "family",fetch = FetchType.EAGER, cascade = CascadeType.ALL, orphanRemoval = true)
    private List<User> users = new ArrayList<>();

    @CreationTimestamp
    private LocalDateTime createdAt;

//    store the number of users in the family
    private int userSize;

    public Family(String familyName) {
        this.familyName = familyName;
    }



}

