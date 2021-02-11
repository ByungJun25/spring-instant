package com.bj25.spring.security.instant.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;

/**
 * <p>
 * This class is for injecting configuration values from external properties
 * (yml) files.
 * 
 * @author bj25
 */
@Setter
@Getter
public class InstantSecurityProperties {

    private DatabaseProperties inMemory = new DatabaseProperties();

    private AjaxProperties ajax = new AjaxProperties();
    private LoginProperties login = new LoginProperties();
    private LogoutProperties logout = new LogoutProperties();
    private PermissionProperties permission = new PermissionProperties();
    private SessionManagementProperties sessionManagement = new SessionManagementProperties();

    // security - cors [key: path, value: configuration]
    private Map<String, CorsProperties> cors = new HashMap<>();

    private CsrfProperties csrf = new CsrfProperties();

    private AuthenticationEntryPointProperties authenticationEntryPoint = new AuthenticationEntryPointProperties();
    private AccessDeniedHandlerProperties accessDeniedHandler = new AccessDeniedHandlerProperties();

    @Setter
    @Getter
    public static class AuthenticationEntryPointProperties {
        private String redirectUrl = "/login?error";
    }

    @Setter
    @Getter
    public static class AccessDeniedHandlerProperties {
        private String redirectUrl = "/error/accessDenied";
    }

    @Setter
    @Getter
    public static class AjaxProperties {
        private String headerKey = "X-Requested-With";
        private String headerValue = "XMLHttpRequest";
        private String authenticationFailureUrl = "/api/exception/authentication";
        private String accessDeniedUrl = "/api/exception/authorization";
    }

    @Setter
    @Getter
    public static class LoginProperties {
        private String page = "/login";
        private String successUrl = "/";
        private String authenticationFailureUrl = "/login?error";
        private String usernameParameter = "username";
    }

    @Setter
    @Getter
    public static class LogoutProperties {
        private boolean invalidateHttpSession = true;
        private boolean clearAuthentication = true;
        private String url = "/logout";
        private String successUrl = "/login?logout";
        private String[] deleteCookies = new String[] { "JSESSIONID" };
    }

    @Setter
    @Getter
    public static class PermissionProperties {
        // [key: httpMethod, value:path]
        private Map<String, String[]> ignorePaths = new HashMap<>();

        // [key: authority name, value: path]
        private Map<String, String[]> permissionUrls = new HashMap<>();

        // [paths]
        private String[] anonymous = new String[] {};

        private String[] all = new String[] {};
    }

    @Setter
    @Getter
    public static class SessionManagementProperties {
        private boolean disabled = false;
        private String creationPolicy = "IF_REQUIRED";
        private boolean enableSessionUrlRewriting = false;
        private String invalidUrl = "/";
        private String authenticationErrorUrl;
        private Integer maximum;
        private FixationProperties fixationProperties = new FixationProperties();
        private ConcurrencyProperties concurrencyProperties = new ConcurrencyProperties();

        @Setter
        @Getter
        public static class ConcurrencyProperties {
            private boolean maxSessionsPreventsLogin = false;
            private String expiredUrl = "/";
        }

        @Setter
        @Getter
        public static class FixationProperties {
            private boolean enabled = false;
            private String type = "NONE";
            private boolean changeSessionId = false;
            private boolean migrateSession = false;
            private boolean newSession = false;
            private boolean none = false;
        }
    }

    @Setter
    @Getter
    public static class CorsProperties {
        private String[] allowedOrigins = new String[] {};
        private String[] allowedHeaders = new String[] {};
        private String[] allowedMethods = new String[] {};
        private boolean allowCredentials = false;
    }

    @Setter
    @Getter
    public static class CsrfProperties {
        private boolean disabled = false;
        private boolean cookieCsrfToken = false;
        private CookieRepository cookieRepository = new CookieRepository();

        @Setter
        @Getter
        public static class CookieRepository {
            private boolean httpOnly = false;
            private boolean secure = false;
            private String cookieDomain = "";
            private String cookiePath = "";
            private String cookieName = "XSRF-TOKEN";
            private String headerName = "X-XSRF-TOKEN";
            private String parameterName = "_csrf";
        }
    }

    @Setter
    @Getter
    public static class DatabaseProperties {
        private boolean enabled = true;
        private List<Client> users = new ArrayList<>();

        @Setter
        @Getter
        public static class Client {
            private String username = "user";
            private String password = "password";
            private String[] roles;
            private boolean accountExpired = false;
            private boolean lock = false;
            private boolean credentialsExpired = false;
            private boolean disabled = false;
        }
    }

}
