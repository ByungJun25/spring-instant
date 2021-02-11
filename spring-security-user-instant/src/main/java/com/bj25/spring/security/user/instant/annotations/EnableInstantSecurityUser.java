package com.bj25.spring.security.user.instant.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.bj25.spring.security.user.instant.config.InstantSecurityUserConfig;

import org.springframework.context.annotation.Import;

/**
 * <p>
 * indicate a spring-security-user-instant module to run.
 * 
 * @author bj25
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(InstantSecurityUserConfig.class)
public @interface EnableInstantSecurityUser {

}
