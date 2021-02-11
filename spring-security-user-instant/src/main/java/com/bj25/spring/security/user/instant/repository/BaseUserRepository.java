package com.bj25.spring.security.user.instant.repository;

import java.util.Optional;

import com.bj25.spring.security.user.instant.model.BaseUser;

import org.springframework.data.repository.NoRepositoryBean;

/**
 * <p>
 * Abstract interface for returning actual User objects.
 * <p>
 * The actual Repository interface should implement this interface and register it as a bean.
 * 
 * @author bj25
 */
@NoRepositoryBean
public interface BaseUserRepository<T extends BaseUser> {

    Optional<T> findByUsername(String username);

    boolean existsByUsername(String username);

}
