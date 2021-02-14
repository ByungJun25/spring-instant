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

package com.bj25.spring.security.instant;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * 
 * @author ByungJun25
 */
@Controller
public class SpringSecuredController {

    @GetMapping
    public String getMappingPermitAll() {
        return "/index";
    }

    @GetMapping("/user")
    public String getMappingUser() {
        return "/user";
    }

    @GetMapping("/admin")
    public String getMappingAdmin() {
        return "/admin";
    }

    @GetMapping("/anonymous")
    public String getMappingAnonymous() {
        return "/anonymous";
    }

    @ResponseBody
    @GetMapping("/ajax")
    public ResponseEntity<Void> getMappingAjax() {
        return ResponseEntity.ok().build();
    }

}
