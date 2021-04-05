package com.bj25.spring.security.instant;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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

@DisplayName("Testing of Instant Security with logging")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(Lifecycle.PER_CLASS)
@ActiveProfiles("logging")
@EnableInstantSecurity
@WebMvcTest
public class InstantSpringSecurityDebugLogTest {
    
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

}
