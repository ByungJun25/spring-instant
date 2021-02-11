package com.bj25.spring.security.user.instant.model;

import java.util.Collection;

/**
 * <p>
 * User interface for UserDetails.
 * <p>
 * The actual User class should implement this interface.
 * 
 * @author bj25
 */
public interface BaseUser {

    String getUsername();

    String getPassword();

    boolean isLock();

    boolean isExpired();

    boolean isEnabled();

    boolean isCredentialExpired();

    Collection<BasePrivilige> getPriviliges();

}
