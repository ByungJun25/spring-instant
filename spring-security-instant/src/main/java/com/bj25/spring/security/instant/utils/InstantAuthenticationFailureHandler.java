package com.bj25.spring.security.instant.utils;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * 폼 로그인 실패시, 이를 핸들링하는 클래스입니다.
 * <p>
 * property로 주어지는 경로로 리다이렉트합니다.
 * 
 * @author bj25
 */
@RequiredArgsConstructor
@Component
public class InstantAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final AjaxHelper ajaxHelper;
    private final InstantSecurityProperties instantSecurityProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException e) throws IOException, ServletException {

        String redirectURL = request.getContextPath() + this.instantSecurityProperties.getAuthenticationEntryPoint().getRedirectUrl();

        if (this.ajaxHelper.isAjaxRequest(request)) {
            redirectURL = request.getContextPath() + this.instantSecurityProperties.getAjax().getAuthenticationFailureUrl();
        }

        response.sendRedirect(redirectURL);
    }

}
