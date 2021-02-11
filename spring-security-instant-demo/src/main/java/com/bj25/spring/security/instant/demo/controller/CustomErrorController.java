package com.bj25.spring.security.instant.demo.controller;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class CustomErrorController implements ErrorController {

    @GetMapping("/error")
    public String handleError(HttpServletRequest request) {
        String path = "/error/index";
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);

        if (status != null) {
            HttpStatus httpStatus = HttpStatus.valueOf(Integer.valueOf(status.toString()));

            switch (httpStatus) {
                case NOT_FOUND:
                    path = "/error/404";
                    break;
                case FORBIDDEN:
                    path = "/error/403";
                    break;
                case INTERNAL_SERVER_ERROR:
                    path = "/error/500";
                    break;
                default:
                    break;
            }
        }

        return path;
    }

    @GetMapping(value = "/error/accessDenied")
    public String handleAccessDeniedError(HttpServletRequest request) {
        return "/error/403";
    }

    @GetMapping(value = "/api/exception/authentication")
    public ResponseEntity<String> handleAjaxAuthenticationError() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Please login.");
    }

    @GetMapping(value = "/api/exception/authorization")
    public ResponseEntity<String> handleAjaxAuthorizationError() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Wrong access.");
    }

    @Override
    public String getErrorPath() {
        return "/error";
    }

}
