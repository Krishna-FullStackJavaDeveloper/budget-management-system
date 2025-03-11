package com.auth.repository;

import com.auth.entity.Family;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FamilyRepository extends JpaRepository<Family, Long> {

    // Find a family by family ID
    Optional<Family> findById(Long id);

    // Find a family by moderator ID
    Optional<Family> findByModeratorId(Long moderatorId);

    // Find a family by the moderator (which should return the family the moderator belongs to)
    Optional<Family> findByModeratorUsername(String moderatorUsername);

    Optional<Family> findByFamilyName(String familyName);
    boolean existsByFamilyName(String familyName);
}
