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

package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import com.bj25.spring.security.instant.annotation.EnableInstantSecurity;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.AccessDeniedHandlerProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.AjaxProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.AuthenticationEntryPointProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CorsProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CsrfProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CsrfProperties.CookieRepository;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.InMemoryUserDetailsServiceProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.LoginProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.LoginProperties.RememberMe;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.LogoutProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.PermissionProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.SessionManagementProperties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * 
 * @author ByungJun25
 */
@DisplayName("Testing - Load InstantSecurity properties.")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("default")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecurityPropertyLoadTest {

    @Autowired
    private InstantSecurityProperties properties;

    @DisplayName("Can load InstantSecurity properties sucessfully.")
    @Order(0)
    @Test
    void load_properties_successfully_test() {
        assertNotNull(this.properties);
    }

    @DisplayName("Can load default values related to inMemory configuration.")
    @Order(10)
    @Test
    void load_inmemory_default_value_successfully_test() {
        // given
        final InMemoryUserDetailsServiceProperties inMemory = this.properties.getInMemory();

        // then
        assertNotNull(inMemory);
        assertFalse(inMemory.isEnabled());
        assertNotNull(inMemory.getUsers());
        assertEquals(0, inMemory.getUsers().size());
    }

    @DisplayName("Can load default values related to login configuration.")
    @Order(20)
    @Test
    void load_login_default_value_successfully_test() {
        // given
        final LoginProperties login = this.properties.getLogin();

        // then
        assertNotNull(login);
        assertEquals("/login", login.getPage());
        assertEquals("/", login.getSuccessUrl());
        assertEquals("/login?error", login.getAuthenticationFailureUrl());
        assertEquals("username", login.getUsernameParameter());
        assertEquals("password", login.getPasswordParameter());

        final RememberMe rememberMe = login.getRememberMe();
        assertNotNull(rememberMe);
        assertFalse(rememberMe.isEnabled());
        assertNull(rememberMe.getAlwaysRemember());
        assertEquals("COOKIE_ONLY", rememberMe.getType());
        assertEquals("rememberMeSecret", rememberMe.getKey());
        assertNull(rememberMe.getCookieDomain());
        assertNull(rememberMe.getSecureCookie());
        assertEquals("remember-me", rememberMe.getCookieName());
        assertEquals("remember-me", rememberMe.getRememberMeParameter());
        assertNull(rememberMe.getTokenValiditySeconds());
    }

    @DisplayName("Can load default values related to logout configuration.")
    @Order(30)
    @Test
    void load_logout_default_value_successfully_test() {
        // given
        final LogoutProperties logout = this.properties.getLogout();

        // then
        assertNotNull(logout);
        assertTrue(logout.isInvalidateHttpSession());
        assertTrue(logout.isClearAuthentication());
        assertEquals("/logout", logout.getUrl());
        assertEquals("/login?logout", logout.getSuccessUrl());
        assertArrayEquals(new String[] { "JSESSIONID" }, logout.getDeleteCookies());
    }

    @DisplayName("Can load default values related to permission configuration.")
    @Order(40)
    @Test
    void load_permission_default_value_successfully_test() {
        // given
        final PermissionProperties permission = this.properties.getPermission();

        // then
        assertNotNull(permission);
        assertNotNull(permission.getIgnorePaths());
        assertEquals(0, permission.getIgnorePaths().size());
        assertNotNull(permission.getPermissionUrls());
        assertEquals(0, permission.getPermissionUrls().size());
        assertNotNull(permission.getAnonymous());
        assertEquals(0, permission.getAnonymous().size());
        assertNotNull(permission.getAll());
        assertEquals(0, permission.getAll().size());
    }

    @DisplayName("Can load default values related to session-management configuration.")
    @Order(50)
    @Test
    void load_sessionManagement_default_value_successfully_test() {
        // given
        final SessionManagementProperties sessionManagement = this.properties.getSessionManagement();

        // then
        assertNotNull(sessionManagement);
        assertEquals("IF_REQUIRED", sessionManagement.getCreationPolicy());
        assertFalse(sessionManagement.isEnableSessionUrlRewriting());
        assertEquals("/", sessionManagement.getInvalidUrl());
        assertNull(sessionManagement.getAuthenticationErrorUrl());
        assertNull(sessionManagement.getMaximum());

        assertNotNull(sessionManagement.getFixationProperties());
        assertFalse(sessionManagement.getFixationProperties().isEnabled());
        assertEquals("NONE", sessionManagement.getFixationProperties().getType());

        assertNotNull(sessionManagement.getConcurrencyProperties());
        assertFalse(sessionManagement.getConcurrencyProperties().isMaxSessionsPreventsLogin());
        assertEquals("/", sessionManagement.getConcurrencyProperties().getExpiredUrl());
    }

    @DisplayName("Can load default values related to CORS configuration.")
    @Order(60)
    @Test
    void load_cors_default_value_successfully_test() {
        // given
        final Map<String, CorsProperties> cors = this.properties.getCors();

        // then
        assertNotNull(cors);
        assertEquals(0, cors.size());
    }

    @DisplayName("Can load default values related to CSRF configuration.")
    @Order(70)
    @Test
    void load_csrf_default_value_successfully_test() {
        // given
        final CsrfProperties csrf = this.properties.getCsrf();

        // then
        assertNotNull(csrf);
        assertFalse(csrf.isDisabled());
        assertFalse(csrf.isCookieCsrfToken());

        final CookieRepository cookieRepository = csrf.getCookieRepository();
        assertNotNull(cookieRepository);
        assertFalse(cookieRepository.isHttpOnly());
        assertFalse(cookieRepository.isSecure());
        assertEquals("", cookieRepository.getCookieDomain());
        assertEquals("", cookieRepository.getCookiePath());
        assertEquals("XSRF-TOKEN", cookieRepository.getCookieName());
        assertEquals("X-XSRF-TOKEN", cookieRepository.getHeaderName());
        assertEquals("_csrf", cookieRepository.getParameterName());
    }

    @DisplayName("Can load default values related to authenticationEntryPoint configuration.")
    @Order(80)
    @Test
    void load_authenticationEntryPoint_default_value_successfully_test() {
        // given
        final AuthenticationEntryPointProperties authenticationEntryPoint = this.properties
                .getAuthenticationEntryPoint();

        // then
        assertNotNull(authenticationEntryPoint);
        assertEquals("/login", authenticationEntryPoint.getRedirectUrl());
    }

    @DisplayName("Can load default values related to accessDeniedHandler configuration.")
    @Order(90)
    @Test
    void load_accessDeniedHandler_default_value_successfully_test() {
        // given
        final AccessDeniedHandlerProperties accessDeniedHandler = this.properties.getAccessDeniedHandler();

        // then
        assertNotNull(accessDeniedHandler);
        assertEquals("/error/accessDenied", accessDeniedHandler.getRedirectUrl());
    }

    @DisplayName("Can load default values related to AJAX configuration.")
    @Order(100)
    @Test
    void load_ajax_default_value_successfully_test() {
        // given
        final AjaxProperties ajax = this.properties.getAjax();

        // then
        assertNotNull(ajax);
        assertEquals("X-Requested-With", ajax.getHeaderKey());
        assertEquals("XMLHttpRequest", ajax.getHeaderValue());
        assertEquals("/api/exception/authentication", ajax.getAuthenticationFailureUrl());
        assertEquals("/api/exception/authorization", ajax.getAccessDeniedUrl());
    }

}
