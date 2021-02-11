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
 * @author bj25
 */
@Getter
public class UserPricipal implements BaseUser, UserDetails {

    private static final long serialVersionUID = 7823815002182193972L;

    private String username;
    private String password;
    private boolean isLock;
    private boolean isExpired;
    private boolean isEnabled;
    private boolean isCredentialExpired;
    private Collection<BasePrivilige> authorities;

    @Builder
    public UserPricipal(String username, String password, boolean isLock, boolean isExpired, boolean isEnabled,
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
