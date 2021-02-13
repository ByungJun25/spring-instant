# spring-security-instant
This is a simple library to apply form based spring security to your prototype application(or toy project) quickly and easily. No more using the same sample code every time, set it through `yaml` and use it right away.

## How it works and why do you made it?
This is works as like simple tutorial code of spring-security project that several blogs explained. Then why do I create this project? As you know, normally we don't need a so complexed security for toy projects(or maybe need it), but we still need to implement same code for security. So I thought that it would be very convenient if I simply can set it through yaml.

## Who is suitable for
* Who doesn't want to spend much time to apply spring security for prototype application or toy project.
* Who doesn't know about spring security but need a spring security for toy project.

## What can you configure via yaml?
* support a form based login and logout.
* support to validate authentication of ajax communication.
* support to configure basic CORS.
* support to configure basic CSRF.
* support to configure rememberMe.
* support to configure basic session management.

## Requirement
* Spring boot 2.4.2+
* Java 8+

## Demo
Please check [spring-security-instant-demo](https://github.com/ByungJun25/spring-instant/tree/main/spring-security-instant-demo) repository

## How to use?

1. Add dependency.  
    You can check the latest version on [Maven Central Repository](#)

    ```xml
    <dependency>
        <groupId>com.github.ByungJun25</groupId>
        <artifactId>spring-security-instant</artifactId>
        <version>1.0.0</version>
    </dependency>
    ```

2. Set up database policy
    1. InMemory Security  
        1. Enable `inMemory` and add clients

            ```yaml
            instant:
            security:
                in-memory:
                ## enable inMemory
                enabled: true
                ## This is just a example. You can add what you want.
                users:
                    - username: user@user.com
                      password: user123
                      roles: USER
                    - username: admin@admin.com
                      password: admin123
                      roles: ADMIN
            ```

    2. Custom database based Security   
        **Implment UserDetailsService and register it as Bean.** 
        
        As you know, if you want to use the custom database based security, you should implement UserDetails and UserDetailsService. If you define and register your own UserDetailsService, then the library will set it on spring security.

        For Example. 
        
        - UserDetails: [spring security user instant - UserPrincipal](https://github.com/ByungJun25/spring-instant/blob/main/spring-security-user-instant/src/main/java/com/bj25/spring/security/user/instant/model/UserPrincipal.java)
        - UserDetailsService: [spring security user instant - DefaultUserDetailsService](https://github.com/ByungJun25/spring-instant/blob/main/spring-security-user-instant/src/main/java/com/bj25/spring/security/user/instant/service/DefaultUserDetailsService.java)

3. Set up permission per URLs.  
    1. ignore-paths - you can set the URLs per HttpMethod to ignore security.

        <details>
        <summary>Example - Click to expand.</summary>

        ```yaml
        instant:
          security:
            permission:
              ignore-paths:
                GET:
                  - /css/**
                  - /js/**
                  - /img/**
        ```

        </details>

    2. permission-urls - you can set the URLs per Authority.

        <details>
        <summary>Example - Click to expand.</summary>

        ```yaml
        instant:
          security:
            permission:
              permission-urls:
                '[ROLE_ADMIN]':
                  - /admin
                '[ROLE_USER]':
                  - /user
        ```

        </details>

    3. all - you can set the URLs for permittAll.

        <details>
        <summary>Example - Click to expand.</summary>

        ```yaml
        instant:
          security:
            permission:
              all:
                - /
        ```

        </details>

    4. anonymous - you can set the URLs for anonymous.

        <details>
        <summary>Example - Click to expand.</summary>

        ```yaml
        instant:
          security:
            permission:
              anonymous:
                - /anonymous
        ```

        </details>

4. (Optional) Set up rememberMe.  
    You can turn on rememberMe option.

    1. COOKIE_ONLY - This uses rememberMe option with cookie.  

        ```yaml
        instant:
          security:
            login:
              remember-me:
                enabled: true
                type: COOKIE_ONLY
                token-validity-seconds: 86400
        ```

    2. PERSISTENT - This uses rememberMe option with database.  
        **For this option, you should implement `PersistentTokenRepository` interface and register it as Bean.**

        For Example.  
        - PersistentTokenRepository: [spring security user instant - RememberMeTokenRepository](https://github.com/ByungJun25/spring-instant/blob/main/spring-security-user-instant/src/main/java/com/bj25/spring/security/user/instant/repository/RememberMeTokenRepository.java)

        Configuration  
        ```yaml
        instant:
          security:
            login:
              remember-me:
                enabled: true
                type: PERSISTENT
                token-validity-seconds: 86400
        ```


5. Declare `@EnableInstantSecurity` on your main class.  

    ```java
    @EnableInstantSecurity
    @SpringBootApplication
    public class SpringSecurityInstantDemoApplication {
        public static void main(String[] args) {
            SpringApplication.run(SpringSecurityInstantDemoApplication.class, args);
        }
    }
    ```

6. (Optional) Configure `application.yml` for custom setting.  
    You can configure the security policy that you want. Please refer [Properties](#Properties) section to know more details.

7. Run the application.

## Properties
Here you can see all properties that you can set up for your own security policy.

#### 1. In memory

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.in-memory.enabled`|boolean|`false`|Enable the InMemoryUserDetailsService.|
|`instant.security.in-memory.users`|List|`Empty List`|Create a new user with the supplied details.|
|`instant.security.in-memory.users.username`|String|`user`|username|
|`instant.security.in-memory.users.password`|String|`password`|password|
|`instant.security.in-memory.users.roles`|String[]|`{}`|roles - Don't write `ROLE_`|
|`instant.security.in-memory.users.accountExpired`|boolean|`false`|isAccountExpired|
|`instant.security.in-memory.users.lock`|boolean|`false`|isLock|
|`instant.security.in-memory.users.credentialsExpired`|boolean|`false`|isCredentialsExpired|
|`instant.security.in-memory.users.disabled`|boolean|`false`|isDisabled|

</details>

#### 2. Form login

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.login.page`|String|`/login`|Specifies the URL to send users to if login is required.|
|`instant.security.login.successUrl`|String|`/`|The URL to be redirected when the user login successfully.|
|`instant.security.login.authentication-failure-url`|String|`/login?error`|The URL to be redirected when the user fails to login.|
|`instant.security.login.username-parameter`|String|`username`|The HTTP parameter to look for the username when performing authentication.|
|`instant.security.login.password-parameter`|String|`password`|The HTTP parameter to look for the password when performing authentication.|
|`instant.security.login.remember-me.enabled`|boolean|`false`|Enable the remeber-me.|
|`instant.security.login.remember-me.always-remember`|Boolean|`null`|Whether the cookie should always be created even if the remember-me parameter is not set.|
|`instant.security.login.remember-me.type`|`COOKIE_ONLY`, `PERSISTENT`|`COOKIE_ONLY`|Type of the remember-me option.|
|`instant.security.login.remember-me.key`|String|`rememberMeSecret`|Sets the key to identify tokens created for remember me authentication.|
|`instant.security.login.remember-me.cookie-domain`|String|`null`|The domain name within which the remember me cookie is visible.|
|`instant.security.login.remember-me.secure-cookie`|Boolean|`null`|Whether the cookie should be flagged as secure or not. Secure cookies can only be sent over an HTTPS connection and thus cannot be accidentally submitted over HTTP where they could be intercepted.|
|`instant.security.login.remember-me.cookie-name`|String|`remember-me`|The name of cookie which store the token for remember me authentication.|
|`instant.security.login.remember-me.remember-me-parameter`|String|`remember-me`|The HTTP parameter used to indicate to remember the user at time of login.|
|`instant.security.login.remember-me.token-validity-seconds`|Integer|`null`|Allows specifying how long (in seconds) a token is valid for.|
</details>

#### 3. Logout

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.logout.invalidate-http-session`|boolean|`true`|Configures SecurityContextLogoutHandler to invalidate the HttpSession at the time of logout.|
|`instant.security.logout.clear-authentication`|boolean|`true`|Specifies if SecurityContextLogoutHandler should clear the Authentication at the time of logout.|
|`instant.security.logout.url`|String|`/logout`|The URL that triggers log out to occur (default is "/logout").|
|`instant.security.logout.success-url`|String|`/login?logout`|The URL to redirect to after logout has occurred.|
|`instant.security.logout.delete-cookies`|String[]|`{ "JSESSIONID" }`|Allows specifying the names of cookies to be removed on logout success.|

</details>

#### 4. Permission per URL

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.permission.ignore-paths.[httpMethod]`|String[]|`{}`|Allows adding RequestMatcher instances that should that Spring Security should ignore.|
|`instant.security.permission.permission-urls.[authorityName]`|String[]|`{}`|The URLs per roles|
|`instant.security.permission.anonymous`|String[]|`{}`|The URLs for anonymous.|
|`instant.security.permission.all`|String[]|`{}`|The URLs for permitAll.|

</details>

#### 5. Session management

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.session-management.disabled`|boolean|`false`|Disable the sessionManagement.|
|`instant.security.session-management.creation-policy`|`ALWAYS`, `IF_REQUIRED`, `NEVER`, `STATELESS`|`IF_REQUIRED`|Allows specifying the SessionCreationPolicy|
|`instant.security.session-management.enable-session-url-rewriting`|boolean|`false`|If set to true, allows HTTP sessions to be rewritten in the URLs when using HttpServletResponse.encodeRedirectURL(String) or HttpServletResponse.encodeURL(String), otherwise disallows HTTP sessions to be included in the URL.|
|`instant.security.session-management.invalid-url`|String|`/`|Setting this attribute will inject the SessionManagementFilter with a SimpleRedirectInvalidSessionStrategy configured with the attribute value.|
|`instant.security.session-management.authentication-error-url`|String|`null`|Defines the URL of the error page which should be shown when the SessionAuthenticationStrategy raises an exception.|
|`instant.security.session-management.maximum`|Integer|`null`|Controls the maximum number of sessions for a user.|
|`instant.security.session-management.fixationProperties.enabled`|boolean|`false`|Enable SessionFixation.|
|`instant.security.session-management.fixationProperties.type`|`CHANGE_SESSION_ID`, `MIGRATE_SESSION`, `NEW_SESSION`, `NONE`|`NONE`|Indicate type of SessionFixation.|
|`instant.security.session-management.concurrencyProperties.max-sessions-prevents-login`|boolean|`false`|If true, prevents a user from authenticating when the maximumSessions(int) has been reached.|
|`instant.security.session-management.concurrencyProperties.expired-url`|String|`/`|The URL to redirect to if a user tries to access a resource and their session has been expired due to too many sessions for the current user.|

</details>

#### 6. CORS

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.cors.[path].allowed-origins`|String[]|`{}`|Variant of setAllowedOrigins(java.util.List<java.lang.String>) for adding one origin at a time.|
|`instant.security.cors.[path].allowed-headers`|String[]|`{}`|Add an actual request header to allow.|
|`instant.security.cors.[path].allowed-methods`|String[]|`{}`|Add an HTTP method to allow.|
|`instant.security.cors.[path].allow-credentials`|boolean|`false`|Whether user credentials are supported.|

</details>

#### 7. CSRF

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.csrf.disabled`|boolean|`false`|Disable the CSRF.|
|`instant.security.csrf.cookie-csrf-token`|boolean|`false`|Specify the CsrfTokenRepository to use.|
|`instant.security.csrf.cookieRepository.http-only`|boolean|`false`|Sets the HttpOnly attribute on the cookie containing the CSRF token.|
|`instant.security.csrf.cookieRepository.secure`|boolean|`false`|Sets secure flag of the cookie that the expected CSRF token is saved to and read from.|
|`instant.security.csrf.cookieRepository.cookie-domain`|String|`Empty`|Sets the domain of the cookie that the expected CSRF token is saved to and read from.|
|`instant.security.csrf.cookieRepository.cookie-path`|String|`Empty`|Set the path that the Cookie will be created with.|
|`instant.security.csrf.cookieRepository.cookie-name`|String|`XSRF-TOKEN`|Sets the name of the cookie that the expected CSRF token is saved to and read from.|
|`instant.security.csrf.cookieRepository.header-name`|String|`X-XSRF-TOKEN`|Sets the name of the HTTP header that should be used to provide the token.|
|`instant.security.csrf.cookieRepository.parameter-name`|String|`_csrf`|Sets the name of the HTTP request parameter that should be used to provide a token.|

</details>

#### 8. AJAX

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.ajax.header-key`|String|`X-Requested-With`|This is the required header key to check when Ajax requests come in.|
|`instant.security.ajax.header-value`|String|`XMLHttpRequest`|The value of the required header element to be compared|
|`instant.security.ajax.authentication-failure-url`|String|`/api/exception/authentication`|The URL to be redirected when unauthenticated users ajax requests come in.|
|`instant.security.ajax.access-denied-url`|String|`/api/exception/authorization`|The URL to be redirected when unauthorized users ajax requests come in.|

</details>

#### 9. AuthenticationEntryPoint

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.authentication-entry-point.redirect-url`|String|`/login?error`|The URL to be redirected when unauthenticated users access the protected resource.|

</details>

#### 10. AccessDeniedHandler

<details>
<summary>Click to expand!</summary>

|Name|type|Default value|Description|
|---|---|---|---|
|`instant.security.access-denied-handler.redirect-url`|String|`/error/accessDenied`|The URL to be redirected when unauthorized users access the protected resource.|

</details>
