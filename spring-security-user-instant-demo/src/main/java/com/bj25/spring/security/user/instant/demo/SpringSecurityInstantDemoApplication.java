package com.bj25.spring.security.user.instant.demo;

import com.bj25.spring.security.user.instant.annotations.EnableInstantSecurityUser;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableInstantSecurityUser
@SpringBootApplication
public class SpringSecurityInstantDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityInstantDemoApplication.class, args);
	}

}
