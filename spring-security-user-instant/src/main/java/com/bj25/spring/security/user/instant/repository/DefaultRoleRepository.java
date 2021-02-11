package com.bj25.spring.security.user.instant.repository;

import java.util.Optional;

import com.bj25.spring.security.user.instant.model.Role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DefaultRoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
