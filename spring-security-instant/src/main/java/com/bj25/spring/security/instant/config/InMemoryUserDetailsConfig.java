package com.bj25.spring.security.instant.config;

import java.util.List;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.InMemoryUserDetailsServiceProperties.Client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class InMemoryUserDetailsConfig {

    private final InstantSecurityProperties instantSecurityProperties;
    private final PasswordEncoder passwordEncoder;

    @ConditionalOnProperty(prefix = InstantSecurityConstants.PREFIX_INSTANT_SECURITY_PROPERTIES, name = "inMemory.enabled", havingValue = "true")
    @Bean
    public UserDetailsService inMemoryUserDetailsManager() {
        final List<Client> users = this.instantSecurityProperties.getInMemory().getUsers();
        final InMemoryUserDetailsManager inMemoryDetailsService = new InMemoryUserDetailsManager();

        if (users == null || users.isEmpty()) {
            return inMemoryDetailsService;
        }

        for (Client u : users) {
            inMemoryDetailsService.createUser(User.builder().username(u.getUsername())
                    .password(this.passwordEncoder.encode(u.getPassword())).roles(u.getRoles())
                    .accountExpired(u.isAccountExpired())
                    .accountLocked(u.isLock())
                    .credentialsExpired(u.isCredentialsExpired())
                    .disabled(u.isDisabled()).build());
        }
        return inMemoryDetailsService;
    }
}
