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

package com.bj25.spring.security.instant.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * 
 * Simple view controller.
 * 
 * @author ByungJun25
 */
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
