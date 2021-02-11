package com.bj25.spring.security.instant.config;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 * Create a {@code InstantSecurityConstants} bean.
 * 
 * @author bj25
 */
@Configuration
public class SecurityPropertiesConfig {

    @Bean(name = InstantSecurityConstants.BEAN_INSTANT_SECURITY_PROPERTIES)
    InstantSecurityProperties securityProperties() {
        return new InstantSecurityProperties();
    }

}
