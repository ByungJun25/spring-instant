package com.bj25.spring.security.user.instant.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RequestMapping("/")
@Controller
public class SimpleController {

    @GetMapping
    public String index() {
        return "/index";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }

    @GetMapping("/register")
    public String register() {
        return "/register";
    }

    @GetMapping("/user")
    public String user() {
        return "/user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "/admin";
    }

    @GetMapping("/mypage")
    public String mypage() {
        return "/mypage";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "/anonymous";
    }

}
