# spring-security-instant
This is a simple library to apply form based spring security to your prototype application(or toy project) quickly and easily. No more using the same sample code every time, set it through yaml, connect your user data and use it right away.

## How it works and why do you made it?
This is works as like simple tutorial code of spring-security project that several blogs explained. Then why do I create this project? As you know, normally we don't need a so complexed security for toy projects(or maybe need it), but we still need to implement same code for security. So I thought that it would be very convenient if I simply can set it through yaml.

## For who
* Who doesn't want to spend time to implement spring security for prototype application or toy project.
* Who doesn't know about spring security but need a spring security for toy project.

## Supported
* form based login and logout.
* validate authentication of ajax communication.
* configure CORS.
* configure CSRF(default, disable and cookieRepository).
* configure session management's creation policy.
* default passwordEncoder.

## Requirement
* Spring boot 2.4.2+
* Java 8+

## Demo
Please check [spring-security-instant-demo](#) repository

## How to use?

1. Add dependency.  

    ```xml
    ```

2. InMemory  

3. Custom  
    1. Implement BaseUser interface.  

        ```java
        ```

    2. Implement BaseUserRepository.  

        ```java
        ```

    3. Register BaseUserRepository bean.  

        ```java
        ```

5. Declare `@EnableInstantSecurity` on your main class.  
    ```java
    ```

6. (Optional) Configure `application.yml` for custom setting.

7. Run the application.

## Properties

