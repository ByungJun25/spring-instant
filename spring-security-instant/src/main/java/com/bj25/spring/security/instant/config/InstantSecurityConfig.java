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

package com.bj25.spring.security.instant.config;

import javax.annotation.PostConstruct;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Spring Security Instant configuration.
 * 
 * <p>
 * It will scan a pacakges of spring-security-instant library.
 * 
 * @author ByungJun25
 */
@Slf4j
@RequiredArgsConstructor
@ComponentScan(basePackages = InstantSecurityConstants.BASE_PACKAGES)
@EnableWebSecurity
@Configuration
public class InstantSecurityConfig {
    private final InstantSecurityProperties instantSecurityProperties;
    private final ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        try {
            log.debug(this.objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(this.instantSecurityProperties));
        } catch (JsonProcessingException e) {
            log.error("Cannot to print InstantSecurityProperties.");
        }
    }
}
