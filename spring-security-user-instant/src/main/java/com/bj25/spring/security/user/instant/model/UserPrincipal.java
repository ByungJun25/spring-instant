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

package com.bj25.spring.security.user.instant.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Builder;
import lombok.Getter;

/**
 * <p>
 * This is a class that implements UserDetails interface.
 * 
 * @author ByungJun25
 */
@Getter
public class UserPrincipal implements BaseUser, UserDetails {

    private static final long serialVersionUID = 7823815002182193972L;

    private String username;
    private String password;
    private boolean isLock;
    private boolean isExpired;
    private boolean isEnabled;
    private boolean isCredentialExpired;
    private Collection<BasePrivilige> authorities;

    @Builder
    public UserPrincipal(String username, String password, boolean isLock, boolean isExpired, boolean isEnabled,
            boolean isCredentialExpired, Collection<BasePrivilige> authorities) {
        this.username = username;
        this.password = password;
        this.isLock = isLock;
        this.isExpired = isExpired;
        this.isEnabled = isEnabled;
        this.isCredentialExpired = isCredentialExpired;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.authorities.isEmpty()) {
            return new ArrayList<>();
        }

        return this.authorities.stream().map(BasePrivilige::getPrivilige).map(n -> new SimpleGrantedAuthority(n))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return (!this.isExpired);
    }

    @Override
    public boolean isAccountNonLocked() {
        return (!this.isLock);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return (!this.isCredentialExpired);
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    @Override
    public Collection<BasePrivilige> getPriviliges() {
        return this.authorities;
    }

}
