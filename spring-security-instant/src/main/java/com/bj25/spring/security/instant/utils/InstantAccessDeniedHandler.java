package com.bj25.spring.security.instant.utils;

import java.io.IOException;
import java.text.MessageFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * 권한 부족으로 접근이 거절 되었을 경우, 이를 핸들링 하는 클래스입니다.
 * <p>
 * property로 주어진 경로로 리다이렉트합니다.
 * 
 * @author bj25
 */
@Slf4j
@RequiredArgsConstructor
@Component
public class InstantAccessDeniedHandler implements AccessDeniedHandler {

    private final AjaxHelper ajaxHelper;
    private final AuthenticationHelper authenticationHelper;
    private final InstantSecurityProperties instantSecurityProperties;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException, ServletException {

        if (authenticationHelper.isAuthenticated()) {
            log.info(MessageFormat.format("[{0}] user attempted to access the protected URL: {1}",
                    authenticationHelper.getUsername(), request.getRequestURI()));
        }

        String redirectURL = request.getContextPath()
                + this.instantSecurityProperties.getAccessDeniedHandler().getRedirectUrl();

        if (this.ajaxHelper.isAjaxRequest(request)) {
            redirectURL = request.getContextPath() + this.instantSecurityProperties.getAjax().getAccessDeniedUrl();
        }

        response.sendRedirect(redirectURL);
    }

}
