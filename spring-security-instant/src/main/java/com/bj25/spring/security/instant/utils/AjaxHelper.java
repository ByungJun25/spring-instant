package com.bj25.spring.security.instant.utils;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * This is a utility class that checks whether the request is a request through
 * Ajax.
 * 
 * @author bj25
 */
@RequiredArgsConstructor
@Component
public class AjaxHelper {

    private final InstantSecurityProperties instantSecurityProperties;

    public boolean isAjaxRequest(HttpServletRequest request) {
        final String ajaxHeader = request.getHeader(this.instantSecurityProperties.getAjax().getHeaderKey());

        if (ajaxHeader != null
                && this.instantSecurityProperties.getAjax().getHeaderValue().equalsIgnoreCase(ajaxHeader)) {
            return true;
        }

        return false;
    }
}
