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

package com.bj25.spring.security.user.instant.demo.config;

import com.bj25.spring.security.user.instant.model.Role;
import com.bj25.spring.security.user.instant.model.User;
import com.bj25.spring.security.user.instant.repository.DefaultUserRepository;
import com.bj25.spring.security.user.instant.repository.DefaultRoleRepository;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Set up default user datas.
 * 
 * @author ByungJun25
 */
@RequiredArgsConstructor
@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    private final DefaultUserRepository userRepository;
    private final DefaultRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {

        if (this.alreadySetup) {
            return;
        }

        Role admin = this.createRoleIfNotFound("ROLE_ADMIN");
        Role user = this.createRoleIfNotFound("ROLE_USER");
        Role guest = this.createRoleIfNotFound("ROLE_GUEST");

        this.createUserIfNotFound("admin@admin.com", passwordEncoder.encode("admin123"), admin);
        this.createUserIfNotFound("user@user.com", passwordEncoder.encode("user123"), user);
        this.createUserIfNotFound("guest@guest.com", passwordEncoder.encode("guest123"), guest);

        this.alreadySetup = true;
    }

    @Transactional
    private void createUserIfNotFound(String email, String password, Role role) {
        User user = this.userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            user = new User(email, password);
            user.addRole(role);
            this.userRepository.save(user);
        }
    }

    @Transactional
    private Role createRoleIfNotFound(String name) {
        Role role = this.roleRepository.findByName(name).orElse(null);

        if (role == null) {
            role = new Role(name);
            role = this.roleRepository.save(role);
        }

        return role;
    }

}
