package com.bj25.spring.security.instant.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.bj25.spring.security.instant.config.SecurityInstantConfig;

import org.springframework.context.annotation.Import;

/**
 * <p>
 * indicate a spring-security-instant module to run.
 * 
 * @author bj25
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(SecurityInstantConfig.class)
public @interface EnableInstantSecurity {
}
