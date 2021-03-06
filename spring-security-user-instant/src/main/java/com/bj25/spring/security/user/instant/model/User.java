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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * <p>
 * User Entity
 * 
 * @author ByungJun25
 */
@NoArgsConstructor
@Getter
@Entity
public class User implements BaseUser {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long Id;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "is_lock")
    private boolean isLock;

    @Column(name = "is_expired")
    private boolean isExpired;

    @Column(name = "is_credential_expired")
    private boolean isCredentialExpired;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Role> roles;

    @Builder
    public User(String email, String password, boolean isLock, boolean isExpired, boolean isCredentialExpired,
            Set<Role> role) {
        this.email = email;
        this.password = password;
        this.isLock = isLock;
        this.isExpired = isExpired;
        this.isCredentialExpired = isCredentialExpired;
        this.roles = role;
    }

    public User(String email, String password) {
        this.email = email;
        this.password = password;
        this.isLock = false;
        this.isExpired = false;
        this.isCredentialExpired = false;
        this.roles = new HashSet<>();
    }

    public void addRole(Role role) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }

        this.roles.add(role);
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isEnabled() {
        return (!this.isLock);
    }

    @Override
    public Collection<BasePrivilige> getPriviliges() {
        return new HashSet<>(this.roles);
    }

}
