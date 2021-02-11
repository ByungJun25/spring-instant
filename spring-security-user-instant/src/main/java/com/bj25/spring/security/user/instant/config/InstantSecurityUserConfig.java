package com.bj25.spring.security.user.instant.config;

import com.bj25.spring.security.instant.annotation.EnableInstantSecurity;
import com.bj25.spring.security.user.instant.constant.InstantSecurityUserConstants;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EntityScan(basePackages = InstantSecurityUserConstants.BASE_PACKAGES)
@EnableJpaRepositories(basePackages = InstantSecurityUserConstants.BASE_PACKAGES)
@ComponentScan(basePackages = InstantSecurityUserConstants.BASE_PACKAGES)
@EnableInstantSecurity
@Configuration
public class InstantSecurityUserConfig {
}
