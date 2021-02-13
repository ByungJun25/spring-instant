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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * <p>
 * This is a utility class to use the values inside the SecurityContextHolder.
 * 
 * @author ByungJun25
 */
@Component
public class AuthenticationHelper {

    public boolean isAuthenticated() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return false;
        }

        return SecurityContextHolder.getContext().getAuthentication().isAuthenticated();
    }

    public Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public String getUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            throw new IllegalStateException("There is no authentication.");
        }

        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

}
