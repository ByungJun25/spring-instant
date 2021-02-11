package com.bj25.spring.security.instant.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * <p>
 * Configuration for passwordEncoder bean.
 * 
 * @author bj25
 */
@Configuration
public class PasswordEncoderConfig {

    /**
     * <p>
     * Create a PasswordEncoder bean, if there is no passwordEncoder bean.
     * 
     * @return
     */
    @ConditionalOnMissingBean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
