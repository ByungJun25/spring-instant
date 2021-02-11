package com.bj25.spring.security.instant.demo;

import com.bj25.spring.security.instant.annotation.EnableInstantSecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableInstantSecurity
@SpringBootApplication
public class SpringSecurityInstantDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityInstantDemoApplication.class, args);
	}

}
