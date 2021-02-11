package com.bj25.spring.security.instant.constants;

/**
 * <p>
 * Hold all of constant value.
 * 
 * @author bj25
 */
public final class InstantSecurityConstants {

    public static final String BASE_PACKAGES = "com.bj25.spring.security.instant";

    public static final String BEAN_INSTANT_CORS_CONFIG_SOURCE = "instantCorsConfigurationSource";
    public static final String BEAN_INSTANT_SECURITY_PROPERTIES = "instantSecurityProperties";
    public static final String PREFIX_INSTANT_SECURITY_PROPERTIES = "instant.security";

    private InstantSecurityConstants() {
        throw new IllegalStateException("Cannot create instance of SecurityConstants");
    }
}
