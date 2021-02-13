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

package com.bj25.spring.security.user.instant.demo.controller;

import com.bj25.spring.security.instant.utils.AuthenticationHelper;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

/**
 * 
 * @author ByungJun25
 */
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
