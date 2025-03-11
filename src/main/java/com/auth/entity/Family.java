package com.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
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

    public void addUser(User user) {
        if (hasMaxUsers()) {
            if (this.users == null) {
                this.users = new ArrayList<>(); // Correct initialization as a List
            }
            this.users.add(user);
            user.setFamily(this);
            this.userSize = this.users.size(); // Ensure userSize updates correctly
        } else {
            throw new RuntimeException("Cannot add more users, family is full.");
        }
    }

    public void removeUser(User user) {
        this.users.remove(user);
        user.setFamily(null);
        this.userSize = users.size(); // Update user size when removing a user
    }

    public boolean hasMaxUsers() {
        return (this.users != null ? this.users.size() : 0) >= 5; // Fix potential null issue
    }

    public void updateUserSize() {
        this.userSize = users.size(); // Ensure the size reflects the current number of users
    }
}

