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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

/**
 * <p>
 * This class is for injecting configuration values from external properties
 * (yaml) files.
 * 
 * @author ByungJun25
 */
@Setter
@Getter
@ConfigurationProperties(InstantSecurityConstants.PREFIX_INSTANT_SECURITY_PROPERTIES)
public class InstantSecurityProperties {

    /**
     * InMemoryUserDetails
     */
    private InMemoryUserDetailsServiceProperties inMemory = new InMemoryUserDetailsServiceProperties();

    /**
     * Configuration for form login.
     */
    private LoginProperties login = new LoginProperties();

    /**
     * Configuration for logout
     */
    private LogoutProperties logout = new LogoutProperties();

    /**
     * Set the paths per roles.
     */
    private PermissionProperties permission = new PermissionProperties();

    /**
     * Configuration for SessionManagement
     */
    private SessionManagementProperties sessionManagement = new SessionManagementProperties();

    /**
     * Configuration for CORS - [key: path, value: CorsProperties]
     */
    private Map<String, CorsProperties> cors = new HashMap<>();

    /**
     * Configuration for CSRF
     */
    private CsrfProperties csrf = new CsrfProperties();

    /**
     * Configuration for AuthenticationEntryPoint
     */
    private AuthenticationEntryPointProperties authenticationEntryPoint = new AuthenticationEntryPointProperties();

    /**
     * Configuration for AccessDeniedHandler
     */
    private AccessDeniedHandlerProperties accessDeniedHandler = new AccessDeniedHandlerProperties();

    /**
     * Configuration for Ajax
     */
    private AjaxProperties ajax = new AjaxProperties();

    /**
     * Configuration for channel security
     */
    private ChannelProperties channel = new ChannelProperties();

    @Getter
    @Setter
    public static class ChannelProperties {
        /**
         * if true, it will configure channel security.
         */
        private boolean enable = false;
        /**
         * if true, any requests will require secure channel 
         */
        private boolean allSecure = false;
        /**
         * The URLs per httpMethod - [key: httpMethod, value: paths]
         */
        private Map<String, String[]> pahtsPerHttpMethod = new HashMap<>();

    }

    @Setter
    @Getter
    public static class AuthenticationEntryPointProperties {
        /**
         * The URL to be redirected when unauthenticated users access the protected
         * resource.
         */
        private String redirectUrl = "/login";
    }

    @Setter
    @Getter
    public static class AccessDeniedHandlerProperties {
        /**
         * The URL to be redirected when unauthorized users access the protected
         * resource.
         */
        private String redirectUrl = "/error/accessDenied";
    }

    @Setter
    @Getter
    public static class AjaxProperties {
        /**
         * This is the required header key to check when Ajax requests come in.
         */
        private String headerKey = "X-Requested-With";

        /**
         * The value of the required header element to be compared
         */
        private String headerValue = "XMLHttpRequest";

        /**
         * The URL to be redirected when unauthenticated users ajax requests come in.
         */
        private String authenticationFailureUrl = "/api/exception/authentication";

        /**
         * The URL to be redirected when unauthorized users ajax requests come in.
         */
        private String accessDeniedUrl = "/api/exception/authorization";
    }

    @Setter
    @Getter
    public static class LoginProperties {
        /**
         * Specifies the URL to send users to if login is required.
         */
        private String page = "/login";

        /**
         * The URL to be redirected when the user login successfully.
         */
        private String successUrl = "/";

        /**
         * The URL to be redirected when the user fails to login.
         */
        private String authenticationFailureUrl = "/login?error";

        /**
         * The HTTP parameter to look for the username when performing authentication.
         */
        private String usernameParameter = "username";

        /**
         * The HTTP parameter to look for the password when performing authentication.
         */
        private String passwordParameter = "password";

        /**
         * Allows configuring of Remember Me authentication.
         */
        private RememberMe rememberMe = new RememberMe();

        @Setter
        @Getter
        public static class RememberMe {
            /**
             * Enable the remeber-me.
             */
            private boolean enabled = false;

            /**
             * Whether the cookie should always be created even if the remember-me parameter
             * is not set.
             */
            private Boolean alwaysRemember;

            /**
             * Type of the remember-me option.
             */
            private String type = "COOKIE_ONLY";

            /**
             * Sets the key to identify tokens created for remember me authentication.
             */
            private String key = "rememberMeSecret";

            /**
             * The domain name within which the remember me cookie is visible.
             */
            private String cookieDomain;

            /**
             * Whether the cookie should be flagged as secure or not. Secure cookies can
             * only be sent over an HTTPS connection and thus cannot be accidentally
             * submitted over HTTP where they could be intercepted.
             */
            private Boolean secureCookie;

            /**
             * The name of cookie which store the token for remember me authentication.
             */
            private String cookieName = "remember-me";

            /**
             * The HTTP parameter used to indicate to remember the user at time of login.
             */
            private String rememberMeParameter = "remember-me";

            /**
             * Allows specifying how long (in seconds) a token is valid for.
             */
            private Integer tokenValiditySeconds;

            public static enum Type {
                COOKIE_ONLY, PERSISTENT;
            }
        }
    }

    @Setter
    @Getter
    public static class LogoutProperties {
        /**
         * Configures SecurityContextLogoutHandler to invalidate the HttpSession at the
         * time of logout.
         */
        private boolean invalidateHttpSession = true;

        /**
         * Specifies if SecurityContextLogoutHandler should clear the Authentication at
         * the time of logout.
         */
        private boolean clearAuthentication = true;

        /**
         * The URL that triggers log out to occur (default is "/logout").
         */
        private String url = "/logout";

        /**
         * The URL to redirect to after logout has occurred.
         */
        private String successUrl = "/login?logout";

        /**
         * Allows specifying the names of cookies to be removed on logout success.
         */
        private String[] deleteCookies = new String[] { "JSESSIONID" };
    }

    @Setter
    @Getter
    public static class PermissionProperties {
        /**
         * Allows adding RequestMatcher instances that should that Spring Security
         * should ignore. - [key: httpMethod, value:paths].
         */
        private Map<String, String[]> ignorePaths = new HashMap<>();

        /**
         * The URLs per roles - [key: path, value: [Key: httpMethod, value:
         * authorities]].
         */
        private Map<String, Map<String, String[]>> permissionUrls = new HashMap<>();

        /**
         * The URLs for anonymous. - [key: httpMethod, value:paths].
         */
        private Map<String, String[]> anonymous = new HashMap<>();

        /**
         * The URLs for permitAll. - [key: httpMethod, value:paths].
         */
        private Map<String, String[]> all = new HashMap<>();
    }

    @Setter
    @Getter
    public static class SessionManagementProperties {
        /**
         * Disable the sessionManagement.
         */
        private boolean disabled = false;

        /**
         * Allows specifying the SessionCreationPolicy
         */
        private String creationPolicy = "IF_REQUIRED";

        /**
         * If set to true, allows HTTP sessions to be rewritten in the URLs when using
         * HttpServletResponse.encodeRedirectURL(String) or
         * HttpServletResponse.encodeURL(String), otherwise disallows HTTP sessions to
         * be included in the URL.
         */
        private boolean enableSessionUrlRewriting = false;

        /**
         * Setting this attribute will inject the SessionManagementFilter with a
         * SimpleRedirectInvalidSessionStrategy configured with the attribute value.
         */
        private String invalidUrl = "/";

        /**
         * Defines the URL of the error page which should be shown when the
         * SessionAuthenticationStrategy raises an exception.
         */
        private String authenticationErrorUrl;

        /**
         * Controls the maximum number of sessions for a user.
         */
        private Integer maximum;

        /**
         * Allows changing the default SessionFixationProtectionStrategy.
         */
        private FixationProperties fixationProperties = new FixationProperties();

        /**
         * Controls the maximum number of sessions for a user.
         */
        private ConcurrencyProperties concurrencyProperties = new ConcurrencyProperties();

        @Setter
        @Getter
        public static class ConcurrencyProperties {
            /**
             * If true, prevents a user from authenticating when the maximumSessions(int)
             * has been reached.
             */
            private boolean maxSessionsPreventsLogin = false;

            /**
             * The URL to redirect to if a user tries to access a resource and their session
             * has been expired due to too many sessions for the current user.
             */
            private String expiredUrl = "/";
        }

        @Setter
        @Getter
        public static class FixationProperties {
            /**
             * Enable SessionFixation.
             */
            private boolean enabled = false;

            /**
             * Indicate type of SessionFixation.(default: {@code NONE})
             */
            private String type = "NONE";

            /**
             * <ul>
             * <li>{@code CHANGE_SESSION_ID}: Specifies that the Servlet container-provided
             * session fixation protection should be used.</li>
             * <li>{@code MIGRATE_SESSION}: Specifies that a new session should be created
             * and the session attributes from the original HttpSession should be
             * retained.</li>
             * <li>{@code NEW_SESSION}: Specifies that a new session should be created, but
             * the session attributes from the original HttpSession should not be
             * retained.</li>
             * <li>{@code NONE}: Specifies that no session fixation protection should be
             * enabled.</li>
             * </ul>
             */
            public static enum FixationType {
                CHANGE_SESSION_ID, MIGRATE_SESSION, NEW_SESSION, NONE;
            }
        }
    }

    @Setter
    @Getter
    public static class CorsProperties {
        /**
         * Variant of setAllowedOrigins(java.util.List<java.lang.String>) for adding one
         * origin at a time.
         */
        private String[] allowedOrigins = new String[] {};

        /**
         * Add an actual request header to allow.
         */
        private String[] allowedHeaders = new String[] {};

        /**
         * Add an HTTP method to allow.
         */
        private String[] allowedMethods = new String[] {};

        /**
         * Whether user credentials are supported.
         */
        private boolean allowCredentials = false;
    }

    @Setter
    @Getter
    public static class CsrfProperties {
        /**
         * Disable the CSRF.
         */
        private boolean disabled = false;

        /**
         * Specify the CsrfTokenRepository to use.
         */
        private boolean cookieCsrfToken = false;

        /**
         * A CsrfTokenRepository that persists the CSRF token in a cookie named
         * "XSRF-TOKEN" and reads from the header "X-XSRF-TOKEN" following the
         * conventions of AngularJS. When using with AngularJS be sure to use
         * withHttpOnlyFalse().
         */
        private CookieRepository cookieRepository = new CookieRepository();

        @Setter
        @Getter
        public static class CookieRepository {
            /**
             * Sets the HttpOnly attribute on the cookie containing the CSRF token.
             */
            private boolean httpOnly = false;

            /**
             * Sets secure flag of the cookie that the expected CSRF token is saved to and
             * read from.
             */
            private boolean secure = false;

            /**
             * Sets the domain of the cookie that the expected CSRF token is saved to and
             * read from.
             */
            private String cookieDomain = "";

            /**
             * Set the path that the Cookie will be created with.
             */
            private String cookiePath = "";

            /**
             * Sets the name of the cookie that the expected CSRF token is saved to and read
             * from.
             */
            private String cookieName = "XSRF-TOKEN";

            /**
             * Sets the name of the HTTP header that should be used to provide the token.
             */
            private String headerName = "X-XSRF-TOKEN";

            /**
             * Sets the name of the HTTP request parameter that should be used to provide a
             * token.
             */
            private String parameterName = "_csrf";
        }
    }

    @Setter
    @Getter
    public static class InMemoryUserDetailsServiceProperties {
        /**
         * Enable the InMemoryUserDetailsService.
         */
        private boolean enabled = false;

        /**
         * Create a new user with the supplied details.
         */
        private List<Client> users = new ArrayList<>();

        @Setter
        @Getter
        public static class Client {
            /**
             * username
             */
            private String username = "user";

            /**
             * password
             */
            private String password = "password";

            /**
             * roles - Don't write {@code ROLE_}
             */
            private String[] roles = new String[] {};

            /**
             * isAccountExpired
             */
            private boolean accountExpired = false;

            /**
             * isLock
             */
            private boolean lock = false;

            /**
             * isCredentialsExpired
             */
            private boolean credentialsExpired = false;

            /**
             * isDisabled
             */
            private boolean disabled = false;
        }
    }

}
