/**
 * Copyright 2021 ByungJun25
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/**
 * <p>
 * Configuration for InMemoryUserDetailsManager Bean.
 * 
 * @author ByungJun25
 */
@RequiredArgsConstructor
@Configuration
public class InMemoryUserDetailsConfig {

    private final InstantSecurityProperties instantSecurityProperties;
    private final PasswordEncoder passwordEncoder;

    /**
     * Create InMemoryUserDetailsManager bean, only if {@code inMemory.enabled} is
     * true.
     * 
     * @return UserDetailsService
     */
    @ConditionalOnProperty(prefix = InstantSecurityConstants.PREFIX_INSTANT_SECURITY_PROPERTIES, name = InstantSecurityConstants.IN_MEMORY_PROPERTY_NAME, havingValue = InstantSecurityConstants.INMEMORY_PROPERTY_VALUE)
    @Bean
    public UserDetailsService inMemoryUserDetailsManager() {
        final List<Client> users = this.instantSecurityProperties.getInMemory().getUsers();
        final InMemoryUserDetailsManager inMemoryDetailsService = new InMemoryUserDetailsManager();

        if (users == null || users.isEmpty()) {
            return inMemoryDetailsService;
        }

        for (Client u : users) {
            inMemoryDetailsService.createUser(
                    User.builder().username(u.getUsername()).password(this.passwordEncoder.encode(u.getPassword()))
                            .roles(u.getRoles()).accountExpired(u.isAccountExpired()).accountLocked(u.isLock())
                            .credentialsExpired(u.isCredentialsExpired()).disabled(u.isDisabled()).build());
        }
        return inMemoryDetailsService;
    }
}
