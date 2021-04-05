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

package com.bj25.spring.security.instant.utils;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * This class handles when an unauthenticated user accesses a protected
 * resource.
 * 
 * @author ByungJun25
 */
@Slf4j
@Component
public class InstantLoginUrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

    private final AjaxHelper ajaxHelper;
    private final InstantSecurityProperties instantSecurityProperties;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public InstantLoginUrlAuthenticationEntryPoint(AjaxHelper ajaxHelper,
            InstantSecurityProperties instantSecurityProperties) {
        super(instantSecurityProperties.getLogin().getPage());
        this.ajaxHelper = ajaxHelper;
        this.instantSecurityProperties = instantSecurityProperties;
        this.setForceHttps(instantSecurityProperties.getLogin().getEntryPointProperty().isForceHttps());
        this.setUseForward(instantSecurityProperties.getLogin().getEntryPointProperty().isUseForward());
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException, ServletException {

        if (!this.ajaxHelper.isAjaxRequest(request)) {
            super.commence(request, response, e);
        } else {
            String redirectURL = this.buildRedirectUrlForAjaxRequest(request, response, e);
            this.redirectStrategy.sendRedirect(request, response, redirectURL);
            return;
        }
    }

    private String buildRedirectUrlForAjaxRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) {
        int serverPort = this.getPortResolver().getServerPort(request);
        String scheme = request.getScheme();
        RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
        urlBuilder.setScheme(scheme);
        urlBuilder.setServerName(request.getServerName());
        urlBuilder.setPort(serverPort);
        urlBuilder.setContextPath(request.getContextPath());
        urlBuilder.setPathInfo(this.instantSecurityProperties.getAjax().getAuthenticationFailureUrl());
        if (this.isForceHttps() && "http".equals(scheme)) {
            Integer httpsPort = this.getPortMapper().lookupHttpsPort(serverPort);
            if (httpsPort != null) {
                // Overwrite scheme and port in the redirect URL
                urlBuilder.setScheme("https");
                urlBuilder.setPort(httpsPort);
            } else {
                log.warn("Unable to redirect to HTTPS as no port mapping found for HTTP port {}", serverPort);
            }
        }
        return urlBuilder.getUrl();
    }

}
