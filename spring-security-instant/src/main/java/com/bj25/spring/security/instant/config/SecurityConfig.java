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
import java.util.Optional;

import com.bj25.spring.security.instant.constants.InstantSecurityConstants;
import com.bj25.spring.security.instant.utils.InstantAccessDeniedHandler;
import com.bj25.spring.security.instant.utils.InstantLoginUrlAuthenticationEntryPoint;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.ChannelProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.CsrfProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.LoginProperties.RememberMe;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.SessionManagementProperties;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties.SessionManagementProperties.FixationProperties.FixationType;
import com.bj25.spring.security.instant.utils.InstantStringUtils;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
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
 * @author ByungJun25
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsConfigurationSource instantCorsConfigurationSource;
    private final InstantSecurityProperties instantSecurityProperties;

    private final Optional<UserDetailsService> userDetailsService;
    private final Optional<PersistentTokenRepository> persistentTokenRepository;

    private final InstantAccessDeniedHandler instantAccessDeniedHandler;
    private final InstantLoginUrlAuthenticationEntryPoint instantLoginUrlAuthenticationEntryPoint;

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
        log.debug("Configure ignored paths.");

        Map<String, String[]> ignorePathsByHttpMethod = this.instantSecurityProperties.getPermission().getIgnorePaths();
        ignorePathsByHttpMethod.forEach((httpMethodName, paths) -> {
            final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
            if (httpMethod != null) {
                web.ignoring().antMatchers(httpMethod, paths);
            } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                web.ignoring().antMatchers(paths);
            }
            log.debug("Ignored paths: [{}] / HttpMethod: [{}]", InstantStringUtils.arrayToString(paths), httpMethodName);
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
        this.exceptionHandlingConfigure(http);
        this.csrfConfigure(http);
        this.ChannelConfigure(http);
    }

    /**
     * <p>
     * Configures channel security.
     * 
     * @param http
     * @throws Exception
     */
    private void ChannelConfigure(HttpSecurity http) throws Exception {
        final ChannelProperties channel = this.instantSecurityProperties.getChannel();
        if (channel.isEnabled()) {
            log.debug("Channel configuration was enabled.");

            ChannelSecurityConfigurer<?>.ChannelRequestMatcherRegistry registry = http.requiresChannel();

            if (channel.isAllSecure()) {
                log.debug("Every paths will be required to use https");

                registry.anyRequest().requiresSecure();
            } else {
                Map<String, String[]> pahtsPerHttpMethod = channel.getSecurePaths();
                pahtsPerHttpMethod.forEach((httpMethodName, paths) -> {
                    final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
                    if (httpMethod != null) {
                        registry.antMatchers(httpMethod, paths).requiresSecure();
                    } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                        registry.antMatchers(paths).requiresSecure();
                    }
                    log.debug("Required to use https - paths: [{}] / HttpMethod: [{}]", InstantStringUtils.arrayToString(paths), httpMethodName);
                });
            }
        }
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
     * Configure anonymous and permitAll path.
     * <p>
     * It will protect any request as default.
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void authorizeRequestConfigure(HttpSecurity http) throws Exception {
        this.anonymousConfigure(http);
        this.permitAllConfigure(http);
        this.denyAllConfigure(http);
        http.authorizeRequests().anyRequest().authenticated();
    }

    /**
     * <p>
     * Configure anonymous path.
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void anonymousConfigure(HttpSecurity http) throws Exception {
        final Map<String, String[]> anonymousUrls = this.instantSecurityProperties.getPermission().getAnonymous();

        for (Entry<String, String[]> entry : anonymousUrls.entrySet()) {
            final String httpMethodName = entry.getKey();
            final String[] paths = entry.getValue();

            final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
            if (httpMethod != null) {
                http.authorizeRequests().antMatchers(httpMethod, paths).anonymous();
            } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                http.authorizeRequests().antMatchers(paths).anonymous();
            }
            log.debug("Required anonymous authorization - paths: [{}] / HttpMethod: [{}]", InstantStringUtils.arrayToString(paths), httpMethodName);
        }
    }

    /**
     * <p>
     * Configure permitAll path.
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void permitAllConfigure(HttpSecurity http) throws Exception {
        this.defaultPermitAll(http);

        final Map<String, String[]> permitAllUrls = this.instantSecurityProperties.getPermission().getAll();

        for (Entry<String, String[]> entry : permitAllUrls.entrySet()) {
            final String httpMethodName = entry.getKey();
            final String[] paths = entry.getValue();

            final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
            if (httpMethod != null) {
                http.authorizeRequests().antMatchers(httpMethod, paths).permitAll();
            } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                http.authorizeRequests().antMatchers(paths).permitAll();
            }
            log.debug("permitAll - paths: [{}] / HttpMethod: [{}]", InstantStringUtils.arrayToString(paths), httpMethodName);
        }
    }

    /**
     * <p>
     * Configure denyAll path.
     * 
     * @see InstantSecurityProperties
     * 
     * @param http
     * @throws Exception
     */
    private void denyAllConfigure(HttpSecurity http) throws Exception {
        this.defaultPermitAll(http);

        final Map<String, String[]> denyAllUrls = this.instantSecurityProperties.getPermission().getDenyAll();

        for (Entry<String, String[]> entry : denyAllUrls.entrySet()) {
            final String httpMethodName = entry.getKey();
            final String[] paths = entry.getValue();

            final HttpMethod httpMethod = HttpMethod.resolve(httpMethodName);
            if (httpMethod != null) {
                http.authorizeRequests().antMatchers(httpMethod, paths).denyAll();
            } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                http.authorizeRequests().antMatchers(paths).denyAll();
            }
            log.debug("denyAll - paths: [{}] / HttpMethod: [{}]", InstantStringUtils.arrayToString(paths), httpMethodName);
        }
    }

    /**
     * <p>
     * Configure permitAll for default failure redirectURLs.
     * 
     * @param http
     * @throws Exception
     */
    private void defaultPermitAll(HttpSecurity http) throws Exception {
        final String defaultAccessDeniedURL = this.instantSecurityProperties.getAccessDeniedHandler().getRedirectUrl();
        final String defaultAjaxAccessDeniedURL = this.instantSecurityProperties.getAjax().getAccessDeniedUrl();
        final String defaultAuthenticationEntryPointURL = this.instantSecurityProperties.getAuthenticationEntryPoint()
                .getRedirectUrl();
        final String defaultAjaxAuthenticationFailureURL = this.instantSecurityProperties.getAjax()
                .getAuthenticationFailureUrl();

        http.authorizeRequests().antMatchers(HttpMethod.GET, defaultAccessDeniedURL, defaultAjaxAccessDeniedURL,
                defaultAuthenticationEntryPointURL, defaultAjaxAuthenticationFailureURL).permitAll();
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
        final boolean isEnableRememberMe = this.instantSecurityProperties.getLogin().getRememberMe().isEnabled();

        http.formLogin().loginPage(loginPage).loginProcessingUrl(loginPage).defaultSuccessUrl(loginSuccessUrl)
                .usernameParameter(usernameParameter).passwordParameter(passwordParameter).failureUrl(failureUrl)
                .permitAll();

        // if rememberMe is enabled.
        if (isEnableRememberMe) {
            this.rememberMe(http);
        }
    }

    /**
     * <p>
     * Configure rememberMe option.
     * 
     * @param http
     * @throws Exception
     */
    private void rememberMe(HttpSecurity http) throws Exception {
        final RememberMe.Type type = RememberMe.Type.valueOf(RememberMe.Type.class,
                this.instantSecurityProperties.getLogin().getRememberMe().getType());

        switch (type) {
            case COOKIE_ONLY:
                this.rememberMeCookieOnly(http);
                break;
            case PERSISTENT:
                this.rememberMePersistent(http);
                break;
            default:
                log.warn("No type for rememberMe configuration, it will be ignored");
                break;
        }
    }

    /**
     * <p>
     * Configure rememberMe option, if the type of rememberMe is COOKIE_ONLY
     * 
     * @param http
     * @throws Exception
     */
    private void rememberMeCookieOnly(HttpSecurity http) throws Exception {
        final String key = this.instantSecurityProperties.getLogin().getRememberMe().getKey();

        RememberMeConfigurer<HttpSecurity> rememberMeConfig = http.rememberMe().key(key);
        this.rememberMeCommon(rememberMeConfig);
    }

    /**
     * <p>
     * Configure rememberMe option, if the type of rememberMe is PERSISTENT
     * 
     * @param http
     * @throws IllegalStateException
     * @throws Exception
     */
    private void rememberMePersistent(HttpSecurity http) throws IllegalStateException, Exception {
        RememberMeConfigurer<HttpSecurity> rememberMeConfig = http.rememberMe()
                .tokenRepository(this.persistentTokenRepository.orElseThrow(() -> new IllegalStateException(
                        "Consider defining a bean of type 'org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;' in your configuration.")));
        this.rememberMeCommon(rememberMeConfig);
    }

    /**
     * <p>
     * Configure common rememberMe option.
     * 
     * @param rememberMeConfig
     */
    private void rememberMeCommon(RememberMeConfigurer<HttpSecurity> rememberMeConfig) {
        final RememberMe rememberMe = this.instantSecurityProperties.getLogin().getRememberMe();
        final String rememberMeParameter = rememberMe.getRememberMeParameter();
        final Integer tokenValiditySeconds = rememberMe.getTokenValiditySeconds();
        final Boolean alwaysRemember = rememberMe.getAlwaysRemember();
        final String cookieDomain = rememberMe.getCookieDomain();
        final String cookieName = rememberMe.getCookieName();
        final Boolean secureCookie = rememberMe.getSecureCookie();

        if (StringUtils.hasText(rememberMeParameter)) {
            rememberMeConfig.rememberMeParameter(rememberMeParameter);
        }

        if (StringUtils.hasText(cookieDomain)) {
            rememberMeConfig.rememberMeCookieDomain(cookieDomain);
        }

        if (StringUtils.hasText(cookieName)) {
            rememberMeConfig.rememberMeCookieName(cookieName);
        }

        if (tokenValiditySeconds != null && tokenValiditySeconds > 0) {
            rememberMeConfig.tokenValiditySeconds(tokenValiditySeconds);
        }

        if (alwaysRemember != null) {
            rememberMeConfig.alwaysRemember(alwaysRemember);
        }

        if (secureCookie != null) {
            rememberMeConfig.useSecureCookie(secureCookie);
        }
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
     * @see InstantLoginUrlAuthenticationEntryPoint
     * 
     * @param http
     * @throws Exception
     */
    private void exceptionHandlingConfigure(HttpSecurity http) throws Exception {
        http.exceptionHandling().accessDeniedHandler(this.instantAccessDeniedHandler)
                .authenticationEntryPoint(this.instantLoginUrlAuthenticationEntryPoint);
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
            http.csrf();
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
     * @return CsrfTokenRepository
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
     * @throws Exception
     */
    private void setPermissionPerUrls(HttpSecurity http) throws Exception {
        final Map<String, Map<String, String[]>> permissionUrls = this.instantSecurityProperties.getPermission()
                .getPermissionUrls();

        for (Entry<String, Map<String, String[]>> entry : permissionUrls.entrySet()) {
            final String path = entry.getKey();
            final Map<String, String[]> authsPerHttpMethod = entry.getValue();

            if(StringUtils.hasText(path)) {
                for (Entry<String, String[]> subEntry : authsPerHttpMethod.entrySet()) {
                    final String[] authorities = subEntry.getValue();
    
                    if(authorities == null || authorities.length == 0) {
                        log.warn("There is no authorities for '{}'. It will be ignored.", path);
                        continue;
                    }
    
                    final String httpMethodName = subEntry.getKey();
                    final HttpMethod o_httpMethod = HttpMethod.resolve(httpMethodName);
                    if (o_httpMethod != null) {
                        http.authorizeRequests().antMatchers(o_httpMethod, path).hasAnyAuthority(authorities);
                    } else if (InstantSecurityConstants.HTTTP_METHOD_ALL_SYMBOL.equals(httpMethodName)) {
                        http.authorizeRequests().antMatchers(path).hasAnyAuthority(authorities);
                    }
                    log.debug("Required authorization - path: [{}] / HttpMethod: [{}] / authorization: [{}]", path, httpMethodName, InstantStringUtils.arrayToString(subEntry.getValue()));
                }
            }
        }
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
