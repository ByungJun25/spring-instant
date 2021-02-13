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
import java.text.MessageFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * This class handles when access is denied due to insufficient privileges.
 * <p>
 * Redirect to the path given by the property.
 * 
 * @author ByungJun25
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class InstantAccessDeniedHandler implements AccessDeniedHandler {

    private final AjaxHelper ajaxHelper;
    private final AuthenticationHelper authenticationHelper;
    private final InstantSecurityProperties instantSecurityProperties;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException, ServletException {

        if (authenticationHelper.isAuthenticated()) {
            log.info(MessageFormat.format("[{0}] user attempted to access the protected URL: {1}",
                    authenticationHelper.getUsername(), request.getRequestURI()));
        }

        String redirectURL = request.getContextPath()
                + this.instantSecurityProperties.getAccessDeniedHandler().getRedirectUrl();

        if (this.ajaxHelper.isAjaxRequest(request)) {
            redirectURL = request.getContextPath() + this.instantSecurityProperties.getAjax().getAccessDeniedUrl();
        }

        response.sendRedirect(redirectURL);
    }

}
