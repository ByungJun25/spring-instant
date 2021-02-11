package com.bj25.spring.security.user.instant.demo.controller;

import com.bj25.spring.security.instant.utils.AuthenticationHelper;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RequestMapping("/api")
@RestController
public class SimpleRestController {

    private final AuthenticationHelper authenticationHelper;

    @GetMapping("/me")
    public ResponseEntity<String> me() {
        return ResponseEntity.ok().body(this.authenticationHelper.getUsername());
    }
}
