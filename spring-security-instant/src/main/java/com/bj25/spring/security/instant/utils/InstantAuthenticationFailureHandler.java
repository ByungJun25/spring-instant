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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * This class handles when form login fails.
 * <p>
 * Redirect to the path given by the property.
 * 
 * @author ByungJun25
 */
@RequiredArgsConstructor
@Component
public class InstantAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final AjaxHelper ajaxHelper;
    private final InstantSecurityProperties instantSecurityProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException e) throws IOException, ServletException {

        String redirectURL = request.getContextPath() + this.instantSecurityProperties.getAuthenticationEntryPoint().getRedirectUrl();

        if (this.ajaxHelper.isAjaxRequest(request)) {
            redirectURL = request.getContextPath() + this.instantSecurityProperties.getAjax().getAuthenticationFailureUrl();
        }

        response.sendRedirect(redirectURL);
    }

}
