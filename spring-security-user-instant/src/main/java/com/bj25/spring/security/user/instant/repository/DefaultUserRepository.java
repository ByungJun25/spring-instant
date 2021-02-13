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

package com.bj25.spring.security.user.instant.repository;

import java.util.Optional;

import com.bj25.spring.security.user.instant.model.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * <p>
 * User repository.
 * 
 * @author ByungJun25
 */
@Repository
public interface DefaultUserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    default Optional<User> findByUsername(String username) {
        return this.findByEmail(username);
    }

    default boolean existsByUsername(String username) {
        return this.existsByEmail(username);
    }

}
