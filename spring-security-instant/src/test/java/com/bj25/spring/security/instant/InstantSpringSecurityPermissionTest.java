package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
//import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;

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
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@DisplayName("Testing of Instant Security")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("permission")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecurityPermissionTest {
    
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

    @DisplayName("Can access ignore paths without authentication successfully")
    @Order(10)
    @Test
    void ignorePathsTest() throws Exception {
        // when
        mvc.perform(get("/css/test.css"))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Can access user page with user role")
    @Order(20)
    @WithMockUser(roles = "USER")
    @Test
    void userRoleTest() throws Exception {
        // when
        mvc.perform(get("/user"))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Can send Post request with user role")
    @Order(21)
    @WithMockUser(roles = "USER")
    @Test
    void userRolePostTest() throws Exception {
        // when
        mvc.perform(post("/user").with(csrf()))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Can send Put request with user role")
    @Order(22)
    @WithMockUser(roles = "USER")
    @Test
    void userRolePutTest() throws Exception {
        // when
        mvc.perform(put("/user").with(csrf()))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Can send Delete request with user role")
    @Order(23)
    @WithMockUser(roles = "USER")
    @Test
    void userRoleDeleteTest() throws Exception {
        // when
        mvc.perform(delete("/user").with(csrf()))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Cannot access user page without authentication")
    @Order(30)
    @Test
    void userRoleFailWithoutAuthenticationTest() throws Exception {
        // when
        mvc.perform(get("/user"))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot send Post user without authentication")
    @Order(31)
    @Test
    void userRolePostFailWithoutAuthenticationTest() throws Exception {
        // when
        mvc.perform(post("/user").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot send Put user without authentication")
    @Order(32)
    @Test
    void userRolePutFailWithoutAuthenticationTest() throws Exception {
        // when
        mvc.perform(put("/user").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot send Delete user without authentication")
    @Order(33)
    @Test
    void userRoleDeleteFailWithoutAuthenticationTest() throws Exception {
        // when
        mvc.perform(delete("/user").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot access user page with other role")
    @Order(40)
    @WithMockUser(roles = "GUEST")
    @Test
    void userRoleFailWithGuestTest() throws Exception {
        // when
        mvc.perform(get("/user"))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/error/accessDenied"));
    }

    @DisplayName("Can access anonymous page with anonymous user")
    @Order(50)
    @WithAnonymousUser
    @Test
    void anonymousTest() throws Exception {
        // when
        mvc.perform(get("/anonymous"))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Cannot access anonymous page with authenticated user")
    @Order(60)
    @WithMockUser
    @Test
    void anonymousFailTest() throws Exception {
        // when
        mvc.perform(get("/anonymous"))

        // then
        .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/error/accessDenied"));
    }

    @DisplayName("Can access permitAll url without authentication successfully")
    @Order(70)
    @Test
    void permitAllTest() throws Exception {
        // when
        mvc.perform(get("/"))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Cannot access denyAll url without authentication - GET")
    @Order(70)
    @Test
    void denyAllGetTest() throws Exception {
        // when
        mvc.perform(get("/deny"))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("http://localhost/login"));
    }


    @DisplayName("Cannot access denyAll url without authentication - POST")
    @Order(71)
    @Test
    void denyAllPostTest() throws Exception {
        // when
        mvc.perform(post("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot access denyAll url without authentication - PUT")
    @Order(72)
    @Test
    void denyAllPutTest() throws Exception {
        // when
        mvc.perform(put("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot access denyAll url without authentication - DELETE")
    @Order(73)
    @Test
    void denyAllDeleteTest() throws Exception {
        // when
        mvc.perform(delete("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("http://localhost/login"));
    }

    @DisplayName("Cannot access denyAll url with authenticated user - GET")
    @Order(74)
    @WithMockUser
    @Test
    void denyAllGetWithAuthenticatedUserTest() throws Exception {
        // when
        mvc.perform(get("/deny"))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl(this.securityProperties.getAccessDeniedHandler().getRedirectUrl()));
    }


    @DisplayName("Cannot access denyAll url with authenticated user - POST")
    @Order(75)
    @WithMockUser
    @Test
    void denyAllPostWithAuthenticatedUserTest() throws Exception {
        // when
        mvc.perform(post("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl(this.securityProperties.getAccessDeniedHandler().getRedirectUrl()));
    }

    @DisplayName("Cannot access denyAll url with authenticated user - PUT")
    @Order(76)
    @WithMockUser
    @Test
    void denyAllPutWithAuthenticatedUserTest() throws Exception {
        // when
        mvc.perform(put("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl(this.securityProperties.getAccessDeniedHandler().getRedirectUrl()));
    }

    @DisplayName("Cannot access denyAll url with authenticated user - DELETE")
    @Order(77)
    @WithMockUser
    @Test
    void denyAllDeleteWithAuthenticatedUserTest() throws Exception {
        // when
        mvc.perform(delete("/deny").with(csrf()))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl(this.securityProperties.getAccessDeniedHandler().getRedirectUrl()));
    }
}
