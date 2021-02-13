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

package com.bj25.spring.security.user.instant.service;

import com.bj25.spring.security.user.instant.model.BaseUser;
import com.bj25.spring.security.user.instant.model.UserPrincipal;
import com.bj25.spring.security.user.instant.repository.DefaultUserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * UserDetailsService. It implements UserDetailsService.
 * 
 * @author ByungJun25
 */
@RequiredArgsConstructor
@Service
public class DefaultUserDetailsService implements UserDetailsService {

    private final DefaultUserRepository userRepository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BaseUser user = this.userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Cannot find a user - username: " + username));

        return UserPrincipal.builder().authorities(user.getPriviliges()).isCredentialExpired(user.isCredentialExpired())
                .isEnabled(user.isEnabled()).isExpired(user.isExpired()).isLock(user.isLock())
                .password(user.getPassword()).username(user.getUsername()).build();
    }
}
