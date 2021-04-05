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

import java.util.Arrays;
import java.util.Map;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantStringUtils;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CorsProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Configuration for cors of security.
 * 
 * @author ByungJun25
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
public class CorsConfig {

    private final InstantSecurityProperties instantSecurityProperties;

    /**
     * <p>
     * create a corsConfigurationSource bean.
     * 
     * <p>
     * properties List:
     * <ul>
     * <li>{@code instant.security.corsConfigurations.[path].allowed-origins}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowedHeaders}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowedMethods}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowCredentials}</li>
     * </ul>
     * 
     * @return CorsConfigurationSource bean named
     *         {@code instantCorsConfigurationSource}
     */
    @Bean(name = InstantSecurityConstants.BEAN_INSTANT_CORS_CONFIG_SOURCE)
    public CorsConfigurationSource corsConfigurationSource() {
        log.debug("Create a CorsConfigurationSource Bean.");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        Map<String, CorsProperties> corsConfigurations = this.instantSecurityProperties.getCors();

        if (corsConfigurations != null && !corsConfigurations.isEmpty()) {
            corsConfigurations.forEach((pattern, config) -> {
                final String[] allowedOrigins = config.getAllowedOrigins();
                final String[] allowedHeaders = config.getAllowedHeaders();
                final String[] allowedMethods = config.getAllowedMethods();
                final boolean allowCredentials = config.isAllowCredentials();

                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
                configuration.setAllowedHeaders(Arrays.asList(allowedHeaders));
                configuration.setAllowedMethods(Arrays.asList(allowedMethods));
                configuration.setAllowCredentials(allowCredentials);

                source.registerCorsConfiguration(pattern, configuration);

                log.debug(
                        "register CORS Configuration - pattern: [{}], allowedOrigins: [{}], allowedHeaders: [{}], allowedMethods: [{}], allowCredentials: [{}]",
                        pattern, InstantStringUtils.arrayToString(allowedOrigins), InstantStringUtils.arrayToString(allowedHeaders),
                        InstantStringUtils.arrayToString(allowedMethods), allowCredentials);
            });
        }

        return source;
    }
}
