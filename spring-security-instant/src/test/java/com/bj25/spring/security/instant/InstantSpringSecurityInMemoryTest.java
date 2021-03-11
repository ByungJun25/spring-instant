package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

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
//import org.springframework.security.test.context.support.WithMockUser;
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

    //@Autowired
    //private ApplicationContext context;

    @DisplayName("Can load all configuration successfully")
    @Order(0)
    @Test
    void load_configuration_successfully() {
        assertNotNull(this.mvc);
        assertNotNull(this.securityProperties);
    }

    @DisplayName("Can login with user successfully")
    @Order(10)
    @Test
    void can_login_with_user() throws Exception {
        // given
        final String username = "user@user.com";
        final String password = "user123";

        // when
        mvc.perform(post("/login").with(csrf()).param("username", username).param("password", password))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/loginSuccess"));
    }

    @DisplayName("Can login with admin successfully")
    @Order(20)
    @Test
    void can_login_with_admin() throws Exception {
        // given
        final String username = "admin@admin.com";
        final String password = "admin123";

        // when
        mvc.perform(post("/login").with(csrf()).param("username", username).param("password", password))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/loginSuccess"));
    }

    @DisplayName("Can login with super admin successfully")
    @Order(30)
    @Test
    void can_login_with_super_admin() throws Exception {
        // given
        final String username = "superAdmin@admin.com";
        final String password = "super123";

        // when
        mvc.perform(post("/login").with(csrf()).param("username", username).param("password", password))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/loginSuccess"));
    }

    @DisplayName("redirect to login page with error parameter, if login is failed.")
    @Order(40)
    @Test
    void redirect_login_page_if_login_failed() throws Exception {
        // when
        mvc.perform(post("/login").with(csrf()).param("username", "test").param("password", "test"))
        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login?error"));
    }

    @DisplayName("Cannot access protected resources withoute authentication")
    @Order(50)
    @Test
    void cannot_access_protected_resources_without_authentication() throws Exception {
        // when
        mvc.perform(get("/")).andExpect(status().is3xxRedirection())
        // then
        .andExpect(redirectedUrl("/login"));
    }

}
