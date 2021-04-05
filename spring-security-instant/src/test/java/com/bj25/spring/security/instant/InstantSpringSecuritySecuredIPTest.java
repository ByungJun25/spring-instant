package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@DisplayName("Testing of Instant Security")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("securedIP")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecuritySecuredIPTest {

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

    @DisplayName("Can access secured path for localhost IP Address with localhost.")
    @Order(80)
    @Test
    void permitLocalhostIPTest() throws Exception {
        // when
        mvc.perform(get("/secured/localhostIP"))

        // then
        .andExpect(status().isOk());
    }

    @DisplayName("Cannot access secured path for specific IP Address with localhost.")
    @Order(90)
    @Test
    void permitRandomIPTest() throws Exception {
        // when
        mvc.perform(get("/secured/randomIP"))

        // then
        .andExpect(status().isForbidden());
    }
}
