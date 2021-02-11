package com.bj25.spring.security.instant.config;

import java.util.Arrays;
import java.util.Map;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CorsProperties;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Configuration for cors of security.
 * 
 * @author bj25
 */
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
            });
        }

        return source;
    }
}
