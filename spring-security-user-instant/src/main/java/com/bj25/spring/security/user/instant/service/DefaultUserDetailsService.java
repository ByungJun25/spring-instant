package com.bj25.spring.security.user.instant.service;

import com.bj25.spring.security.user.instant.model.BaseUser;
import com.bj25.spring.security.user.instant.model.UserPricipal;
import com.bj25.spring.security.user.instant.repository.DefaultUserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class DefaultUserDetailsService implements UserDetailsService {

    private final DefaultUserRepository userRepository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BaseUser user = this.userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Cannot find a user - username: " + username));

        return UserPricipal.builder().authorities(user.getPriviliges()).isCredentialExpired(user.isCredentialExpired())
                .isEnabled(user.isEnabled()).isExpired(user.isExpired()).isLock(user.isLock())
                .password(user.getPassword()).username(user.getUsername()).build();
    }
}
