package com.bj25.spring.security.user.instant.repository;

import java.util.Optional;

import com.bj25.spring.security.user.instant.model.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultUserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    default Optional<User> findByUsername(String username) {
        return this.findByEmail(username);
    }

    default boolean existsByUsername(String username) {
        return this.existsByEmail(username);
    }

}
