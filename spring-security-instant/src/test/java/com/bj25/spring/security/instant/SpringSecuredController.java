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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 
 * @author ByungJun25
 */
@RestController
public class SpringSecuredController {

    @GetMapping
    public ResponseEntity<String> getMappingPermitAll() {
        return ResponseEntity.ok().body("permitAll - get");
    }

    @PostMapping
    public ResponseEntity<String> postMappingPermitAll() {
        return ResponseEntity.ok().body("permitAll - post");
    }

    @PutMapping
    public ResponseEntity<String> putMappingPermitAll() {
        return ResponseEntity.ok().body("permitAll - put");
    }

    @DeleteMapping
    public ResponseEntity<String> deleteMappingPermitAll() {
        return ResponseEntity.ok().body("permitAll - delete");
    }

    @GetMapping("/user")
    public ResponseEntity<String> getMappingUser() {
        return ResponseEntity.ok().body("user - get");
    }

    @PostMapping("/user")
    public ResponseEntity<String> postMappingUser() {
        return ResponseEntity.ok().body("user - post");
    }

    @PutMapping("/user")
    public ResponseEntity<String> putMappingUser() {
        return ResponseEntity.ok().body("user - put");
    }

    @DeleteMapping("/user")
    public ResponseEntity<String> deleteMappingUser() {
        return ResponseEntity.ok().body("user - update");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> getMappingAdmin() {
        return ResponseEntity.ok().body("admin - get");
    }

    @PostMapping("/admin")
    public ResponseEntity<String> postMappingAdmin() {
        return ResponseEntity.ok().body("admin - post");
    }

    @PutMapping("/admin")
    public ResponseEntity<String> putMappingAdmin() {
        return ResponseEntity.ok().body("admin - put");
    }

    @DeleteMapping("/admin")
    public ResponseEntity<String> deleteMappingAdmin() {
        return ResponseEntity.ok().body("admin - delete");
    }

    @GetMapping("/anonymous")
    public ResponseEntity<String> getMappingAnonymous() {
        return ResponseEntity.ok().body("anonymous - get");
    }

    @PostMapping("/anonymous")
    public ResponseEntity<String> postMappingAnonymous() {
        return ResponseEntity.ok().body("anonymous - post");
    }

    @PutMapping("/anonymous")
    public ResponseEntity<String> putMappingAnonymous() {
        return ResponseEntity.ok().body("anonymous - put");
    }

    @DeleteMapping("/anonymous")
    public ResponseEntity<String> deleteMappingAnonymous() {
        return ResponseEntity.ok().body("anonymous - delete");
    }

    @ResponseBody
    @GetMapping("/ajax")
    public ResponseEntity<Void> getMappingAjax() {
        return ResponseEntity.ok().build();
    }

    @GetMapping("/secured")
    public ResponseEntity<Void> securedChannelMapping() {
        return ResponseEntity.ok().build();
    }

}
