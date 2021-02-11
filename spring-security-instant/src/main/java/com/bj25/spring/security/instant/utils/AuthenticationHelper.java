package com.bj25.spring.security.instant.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * <p>
 * This is a utility class to use the values inside the SecurityContextHolder.
 * 
 * @author bj25
 */
@Component
public class AuthenticationHelper {

    public boolean isAuthenticated() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return false;
        }

        return SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
    }

    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public String getUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            throw new IllegalStateException("There is no authentication.");
        }

        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

}
