package com.bj25.spring.security.instant.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.bj25.spring.security.instant.utils.InstantAccessDeniedHandler;
import com.bj25.spring.security.instant.utils.InstantAuthenticationEntryPoint;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CsrfProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.SessionManagementProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.SessionManagementProperties.FixationProperties.FixationType;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Configuration for Spring Security
 * 
 * @author bj25
 */
@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsConfigurationSource instantCorsConfigurationSource;
    private final InstantSecurityProperties instantSecurityProperties;

    private final Optional<UserDetailsService> userDetailsService;

    private final InstantAccessDeniedHandler instantAccessDeniedHandler;
    private final InstantAuthenticationEntryPoint instantAuthenticationEntryPoint;

    private final PasswordEncoder passwordEncoder;

    /**
     * <p>
     * Congfigure WebSecurity.
     * <p>
     * It will set the ignore paths per {@code HttpMethod} which was defined in
     * properties file.
     * <p>
     * properties - {@code instant.security.ignore-paths.{HttpMethod}.{paths}}
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        Map<String, String[]> ignorePathsByHttpMethod = this.instantSecurityProperties.getPermission().getIgnorePaths();
        ignorePathsByHttpMethod.forEach((httpMethodName, paths) -> {
            final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
            if (httpMethod != null) {
                web.ignoring().antMatchers(httpMethod, paths);
            }
        });
    }

    /**
     * <p>
     * Configure HttpSecurity
     * <p>
     * It will set permission for each paths which was defined in properties file.
     * And also it will set other configuration properties for {@code formLogin},
     * {@code logout}, {@code cors}, {@code csrf}, {@code sessionManageMent}.
     * <p>
     * Default: allow all paths without secure.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        this.setPermissionPerUrls(http);
        this.corsConfigure(http);
        this.authorizeRequestConfigure(http);
        this.formLoginConfigure(http);
        this.logoutConfigure(http);
        this.sessionManageMentConfigure(http);
        this.ExceptionHandlingConfigure(http);
        this.csrfConfigure(http);
    }

    /**
     * <p>
     * Configure CORS
     * <p>
     * It will configure CORS with properties.
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.corsConfigurations.[path].allowedOrigins}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowedHeaders}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowedMethods}</li>
     * <li>{@code instant.security.corsConfigurations.[path].allowCredentials}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * @see CorsConfig
     * 
     * @param http
     * @throws Exception
     */
    private void corsConfigure(HttpSecurity http) throws Exception {
        http.cors().configurationSource(this.instantCorsConfigurationSource);
    }

    /**
     * <p>
     * Configure a security for paths.
     * <p>
     * A default action is that it allows all paths.
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.authenticated-only-urls.[path]}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void authorizeRequestConfigure(HttpSecurity http) throws Exception {
        final String[] anonymousUrls = this.instantSecurityProperties.getPermission().getAnonymous();
        final String[] permitAllUrls = this.instantSecurityProperties.getPermission().getAll();

        http.authorizeRequests().antMatchers(anonymousUrls).anonymous().antMatchers(permitAllUrls).permitAll()
                .anyRequest().authenticated();
    }

    /**
     * <p>
     * Configure form login.
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.loginPage}</li>
     * <li>{@code instant.security.loginSuccessUrl}</li>
     * <li>{@code instant.security.usernameParameter}</li>
     * <li>{@code instant.security.authenticationFailureUrl}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void formLoginConfigure(HttpSecurity http) throws Exception {
        final String loginPage = this.instantSecurityProperties.getLogin().getPage();
        final String loginSuccessUrl = this.instantSecurityProperties.getLogin().getSuccessUrl();
        final String usernameParameter = this.instantSecurityProperties.getLogin().getUsernameParameter();
        final String failureUrl = this.instantSecurityProperties.getLogin().getAuthenticationFailureUrl();
        final String passwordParameter = this.instantSecurityProperties.getLogin().getPasswordParameter();

        http.formLogin().loginPage(loginPage).loginProcessingUrl(loginPage).defaultSuccessUrl(loginSuccessUrl)
                .usernameParameter(usernameParameter).passwordParameter(passwordParameter).failureUrl(failureUrl).permitAll();
    }

    /**
     * <p>
     * Configure logout
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.logoutUrl}</li>
     * <li>{@code instant.security.logoutSuccessURl}</li>
     * <li>{@code instant.security.deleteCookies.[values]}</li>
     * <li>{@code instant.security.invalidateHttpSession}</li>
     * <li>{@code instant.security.clearAuthentication}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void logoutConfigure(HttpSecurity http) throws Exception {
        final String logoutUrl = this.instantSecurityProperties.getLogout().getUrl();
        final String logoutSuccessUrl = this.instantSecurityProperties.getLogout().getSuccessUrl();
        final String[] deleteCookies = this.instantSecurityProperties.getLogout().getDeleteCookies();
        final boolean isInvalidateHttpSession = this.instantSecurityProperties.getLogout().isInvalidateHttpSession();
        final boolean isClearAuthentication = this.instantSecurityProperties.getLogout().isClearAuthentication();

        http.logout().logoutUrl(logoutUrl).invalidateHttpSession(isInvalidateHttpSession)
                .clearAuthentication(isClearAuthentication).deleteCookies(deleteCookies)
                .logoutSuccessUrl(logoutSuccessUrl).permitAll();
    }

    /**
     * <p>
     * Configure SessionManageMent
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.sessionCreationPolicy}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void sessionManageMentConfigure(HttpSecurity http) throws Exception {
        SessionManagementProperties sessionManagementProperties = this.instantSecurityProperties.getSessionManagement();

        if (sessionManagementProperties.isDisabled()) {
            http.sessionManagement().disable();
            return;
        }

        if (StringUtils.hasText(sessionManagementProperties.getCreationPolicy())) {
            final SessionCreationPolicy policy = SessionCreationPolicy.valueOf(SessionCreationPolicy.class,
                    sessionManagementProperties.getCreationPolicy());
            http.sessionManagement().sessionCreationPolicy(policy);
        }

        if (sessionManagementProperties.isEnableSessionUrlRewriting()) {
            http.sessionManagement().enableSessionUrlRewriting(true);
        }

        if (StringUtils.hasText(sessionManagementProperties.getInvalidUrl())) {
            http.sessionManagement().invalidSessionUrl(sessionManagementProperties.getInvalidUrl());
        }

        if (StringUtils.hasText(sessionManagementProperties.getAuthenticationErrorUrl())) {
            http.sessionManagement()
                    .sessionAuthenticationErrorUrl(sessionManagementProperties.getAuthenticationErrorUrl());
        }

        if (sessionManagementProperties.getMaximum() != null) {
            final String expiredUrl = sessionManagementProperties.getConcurrencyProperties().getExpiredUrl();
            final boolean maxSessionsPreventsLogin = sessionManagementProperties.getConcurrencyProperties()
                    .isMaxSessionsPreventsLogin();

            http.sessionManagement().maximumSessions(sessionManagementProperties.getMaximum()).expiredUrl(expiredUrl)
                    .maxSessionsPreventsLogin(maxSessionsPreventsLogin);
        }

        if (sessionManagementProperties.getFixationProperties().isEnabled()) {
            final FixationType type = FixationType.valueOf(FixationType.class,
                    sessionManagementProperties.getFixationProperties().getType());

            switch (type) {
                case NONE:
                    http.sessionManagement().sessionFixation().none();
                    break;
                case CHANGE_SESSION_ID:
                    http.sessionManagement().sessionFixation().changeSessionId();
                    break;
                case MIGRATE_SESSION:
                    http.sessionManagement().sessionFixation().migrateSession();
                    break;
                case NEW_SESSION:
                    http.sessionManagement().sessionFixation().newSession();
                    break;
                default:
                    http.sessionManagement().sessionFixation();
                    break;
            }
        }
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
     * @see InstantAuthenticationEntryPoint
     * 
     * @param http
     * @throws Exception
     */
    private void ExceptionHandlingConfigure(HttpSecurity http) throws Exception {
        http.exceptionHandling().accessDeniedHandler(this.instantAccessDeniedHandler)
                .authenticationEntryPoint(this.instantAuthenticationEntryPoint);
    }

    /**
     * <p>
     * Configure CSRF
     * <p>
     * If disabled {@code true}, the csrf will be disabled, otherwise csrf will be
     * abled.
     * <p>
     * If cookieCsrfToken is {@code true}, it will set the
     * CookieCSRFTokenRepository.
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.csrfConfiguration.disabled}</li>
     * <li>{@code instant.security.csrfConfiguration.cookieCsrfToken}</li>
     * </ul>
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void csrfConfigure(HttpSecurity http) throws Exception {
        CsrfProperties csrfProperties = this.instantSecurityProperties.getCsrf();

        if (csrfProperties == null) {
            log.info("Apply default CSRF configuration.");
            return;
        }

        final boolean disabled = csrfProperties.isDisabled();
        final boolean cookieCsrfToken = csrfProperties.isCookieCsrfToken();

        if (disabled) {
            http.csrf().disable();
            return;
        }

        if (cookieCsrfToken) {
            CsrfTokenRepository repository = this.generateCookieCsrfTokenRepository(csrfProperties);
            http.csrf().csrfTokenRepository(repository);
            return;
        }

        http.csrf();
    }

    /**
     * <p>
     * Configure CookeCSRFTokenRepository
     * <p>
     * It will configure CookeCSRFTokenRepository with properties.
     * <p>
     * properties:
     * <ul>
     * <li>{@code instant.security.csrfConfiguration.httpOnly}</li>
     * <li>{@code instant.security.csrfConfiguration.secure}</li>
     * <li>{@code instant.security.csrfConfiguration.cookieDomain}</li>
     * <li>{@code instant.security.csrfConfiguration.cookiePath}</li>
     * <li>{@code instant.security.csrfConfiguration.cookieName}</li>
     * <li>{@code instant.security.csrfConfiguration.headerName}</li>
     * <li>{@code instant.security.csrfConfiguration.parameterName}</li>
     * </ul>
     * 
     * @param csrfProperties
     * @return
     */
    private CsrfTokenRepository generateCookieCsrfTokenRepository(CsrfProperties csrfProperties) {
        final boolean httpOnly = csrfProperties.getCookieRepository().isHttpOnly();
        final boolean secure = csrfProperties.getCookieRepository().isSecure();
        final String cookieDomain = csrfProperties.getCookieRepository().getCookieDomain();
        final String cookiePath = csrfProperties.getCookieRepository().getCookiePath();
        final String cookieName = csrfProperties.getCookieRepository().getCookieName();
        final String headerName = csrfProperties.getCookieRepository().getHeaderName();
        final String parameterName = csrfProperties.getCookieRepository().getParameterName();

        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();

        repository.setCookieDomain(cookieDomain);
        repository.setCookieHttpOnly(httpOnly);
        repository.setCookieName(cookieName);
        repository.setCookiePath(cookiePath);
        repository.setHeaderName(headerName);
        repository.setParameterName(parameterName);
        repository.setSecure(secure);
        return repository;
    }

    /**
     * <p>
     * Configurate permission per paths.
     * 
     * @param http
     * @param authsPerUrl
     * @throws Exception
     */
    private void setPermissionPerUrls(HttpSecurity http) throws Exception {
        final Map<String, List<String>> authsPerUrl = this
                .getAuthsPerUrlMap(this.instantSecurityProperties.getPermission().getPermissionUrls());

        for (Map.Entry<String, List<String>> entry : authsPerUrl.entrySet()) {
            final String url = entry.getKey();
            String[] authorities = entry.getValue().toArray(new String[0]);
            http.authorizeRequests().antMatchers(url).hasAnyAuthority(authorities);
        }
    }

    /**
     * <p>
     * Change the list of path per authority to list of authority per path.
     * 
     * @param authUrls
     * @return list of authority per path
     */
    private Map<String, List<String>> getAuthsPerUrlMap(Map<String, String[]> authUrls) {
        Map<String, List<String>> resultMap = new HashMap<>();

        authUrls.forEach((auth, urls) -> {
            for (String url : urls) {
                if (resultMap.containsKey(url)) {
                    List<String> auths = resultMap.get(url);
                    auths.add(auth);
                } else {
                    List<String> auths = new ArrayList<>();
                    auths.add(auth);
                    resultMap.put(url, auths);
                }
            }
        });

        return resultMap;
    }

    /**
     * <p>
     * Configure {@code UserDetailsService} and {@code PasswordEncoder}
     * 
     * @see PasswordEncoderConfig
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);

        auth.userDetailsService(this.userDetailsService.orElseThrow(() -> new IllegalStateException(
                "Consider defining a bean of type 'org.springframework.security.core.userdetails.UserDetailsService;' in your configuration.")))
                .passwordEncoder(this.passwordEncoder);
    }

}
