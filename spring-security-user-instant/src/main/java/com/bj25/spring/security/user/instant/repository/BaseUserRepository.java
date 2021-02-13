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

import com.bj25.spring.security.user.instant.model.BaseUser;

import org.springframework.data.repository.NoRepositoryBean;

/**
 * <p>
 * Abstract interface for returning actual User objects.
 * <p>
 * The actual Repository interface should implement this interface and register it as a bean.
 * 
 * @author ByungJun25
 */
@NoRepositoryBean
public interface BaseUserRepository<T extends BaseUser> {

    Optional<T> findByUsername(String username);

    boolean existsByUsername(String username);

}
