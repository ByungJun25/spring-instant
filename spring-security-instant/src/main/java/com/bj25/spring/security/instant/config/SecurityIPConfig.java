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

import java.util.Map;
import java.util.Map.Entry;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantAccessDeniedHandler;
import com.bj25.spring.security.instant.utils.InstantHttp403ForbiddenEntryPoint;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;

import org.apache.commons.validator.routines.InetAddressValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Configuration for Spring Security for IP-Address
 * <p>
 * This configuration will be start, only if {@code instant.security.secured-ip.enabled} is {@code true}
 * 
 * @author ByungJun25
 */
@Slf4j
@RequiredArgsConstructor
@Order(1)
@ConditionalOnProperty(prefix = InstantSecurityConstants.PREFIX_INSTANT_SECURITY_PROPERTIES, name = InstantSecurityConstants.SECURED_IP_PROPERTY_NAME, havingValue = InstantSecurityConstants.TRUE)
@Configuration
public class SecurityIPConfig extends WebSecurityConfigurerAdapter {

    private final InstantSecurityProperties instantSecurityProperties;

    private final InstantAccessDeniedHandler instantAccessDeniedHandler;
    private final InstantHttp403ForbiddenEntryPoint instantHttp403ForbiddenEntryPoint;

    private final InetAddressValidator inetAddressValidator = InetAddressValidator.getInstance();
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher(this.instantSecurityProperties.getSecuredIp().getBasePathPattern());
        this.setPermissionPerIPAdress(http);
        this.exceptionHandlingConfigure(http);
    }

    /**
     * <p>
     * Configure ExceptionHandling
     * <p>
     * It will add {@code AccessDeniedHandler} and {@code AuthenticationEntryPoint}
     * <p>
     * 
     * @see InstantSecurityProperties
     * @see InstantAccessDeniedHandler
     * @see InstantHttp403ForbiddenEntryPoint
     * 
     * @param http
     * @throws Exception
     */
    private void exceptionHandlingConfigure(HttpSecurity http) throws Exception {
        http.exceptionHandling().accessDeniedHandler(this.instantAccessDeniedHandler)
                .authenticationEntryPoint(this.instantHttp403ForbiddenEntryPoint);
    }

    /**
     * <p>
     * Configurate permission per IP-Address.
     * 
     * @param http
     * @throws Exception
     */
    private void setPermissionPerIPAdress(HttpSecurity http) throws Exception {
        final Map<String, Map<String, String>> permissionIPs = this.instantSecurityProperties.getSecuredIp().getPermissions();

        for (Entry<String, Map<String, String>> entry : permissionIPs.entrySet()) {
            final String path = this.buildPath(entry.getKey());
            final Map<String, String> ipAddressesPerHttpMethod = entry.getValue();

            if(StringUtils.hasText(path)) {
                for (Entry<String, String> subEntry : ipAddressesPerHttpMethod.entrySet()) {
                    final String ipAddress = subEntry.getValue();

                    if(!StringUtils.hasText(ipAddress)) {
                        log.warn("There is no IP-Address for '{}'. It will be ignored.", path);
                        continue;
                    }

                    if(!this.inetAddressValidator.isValid(ipAddress)) {
                        log.warn("It is not validated IP-Address - '{}'. It will be ignored.", ipAddress);
                        continue;
                    }

                    final String httpMethodName = subEntry.getKey();
                    final HttpMethod o_httpMethod = HttpMethod.resolve(httpMethodName);
                    if (o_httpMethod != null) {
                        http.authorizeRequests().antMatchers(o_httpMethod, path).hasIpAddress(ipAddress);
                    } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                        http.authorizeRequests().antMatchers(path).hasIpAddress(ipAddress);
                    }
                    log.debug("Required IP-Address - path: [{}] / HttpMethod: [{}] / IP-Address: [{}]", path, httpMethodName, ipAddress);
                }
            }
        }
    }

    private String buildPath(String subPath) {
        if(!StringUtils.hasText(subPath)) {
            return "";
        }

        final String basePath = this.instantSecurityProperties.getSecuredIp().getBasePathPattern();
        return String.join("", basePath, subPath);
    }
}
