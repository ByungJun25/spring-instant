package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.bj25.spring.security.instant.annotation.EnableInstantSecurity;
import com.bj25.spring.security.instant.utils.InstantSecurityProperties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@DisplayName("Testing of Instant Security with InMemory")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("inMemory")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecurityInMemoryTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private InstantSecurityProperties securityProperties;

    @DisplayName("Can load all configuration successfully")
    @Order(0)
    @Test
    void load_configuration_successfully() {
        assertNotNull(this.mvc);
        assertNotNull(this.securityProperties);
    }

    @DisplayName("Available to register users by YAML")
    @Order(1)
    @Test
    void available_register_users_by_YAML() throws Exception {
        // given
        final String username = "user@user.com";
        final String password = "user123";

        // when
        mvc.perform(post("/login").param("username", username).param("password", password)).andExpect(status().is3xxRedirection()).andExpect(view().name("/"));
    }

    @DisplayName("Can load index page without any authentication")
    @Order(10)
    @Test
    void can_load_index_without_authentication_successfully() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk()).andExpect(view().name("/index"));
    }

    @WithMockUser()
    @DisplayName("Can load user index page with user role")
    @Order(20)
    @Test
    void can_load_user_index_with_user_role() {
        assertNotNull(this.mvc);
        assertNotNull(this.securityProperties);
    }

}
