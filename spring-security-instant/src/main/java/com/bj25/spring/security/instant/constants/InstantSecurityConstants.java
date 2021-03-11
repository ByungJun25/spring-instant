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

package com.bj25.spring.security.instant.constants;

/**
 * <p>
 * Hold all of constant value.
 * 
 * @author ByungJun25
 */
public final class InstantSecurityConstants {

    public static final String BASE_PACKAGES = "com.bj25.spring.security.instant";

    public static final String BEAN_INSTANT_CORS_CONFIG_SOURCE = "instantCorsConfigurationSource";
    public static final String BEAN_INSTANT_SECURITY_PROPERTIES = "instantSecurityProperties";
    public static final String PREFIX_INSTANT_SECURITY_PROPERTIES = "instant.security";
    public static final String IN_MEMORY_PROPERTY_NAME = "in-memory.enabled";
    public static final String INMEMORY_PROPERTY_VALUE = "true";
    public static final String HTTTP_METHOD_ALL_SYMBOL = "*";

    private InstantSecurityConstants() {
        throw new IllegalStateException("Cannot create instance of SecurityConstants");
    }
}
