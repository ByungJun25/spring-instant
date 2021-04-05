package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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

@DisplayName("Testing of Instant Security with Channel properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("channel")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecurityChannelTest {
    
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

    @DisplayName("cannot access secured path with http")
    @Order(10)
    @Test
    void securedPathTest() throws Exception {
        // when
        this.mvc.perform(get("/secured"))

        // then
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("https://localhost/secured"));
    }

    @DisplayName("can access insecured path with http")
    @Order(20)
    @Test
    void test2() throws Exception {
        // when
        this.mvc.perform(get("/"))

        // then
        .andExpect(status().isOk());
    }
}
