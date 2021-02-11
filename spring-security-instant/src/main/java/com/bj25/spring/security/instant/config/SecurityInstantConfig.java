package com.bj25.spring.security.instant.config;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 * Spring Security Instant configuration.
 * 
 * <p>
 * It will scan a pacakges of spring-security-instant library.
 * 
 * @author bj25
 */
@ComponentScan(basePackages = InstantSecurityConstants.BASE_PACKAGES)
@Configuration
public class SecurityInstantConfig {
}
