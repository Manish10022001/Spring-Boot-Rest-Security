package com.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//step 1
@Configuration
public class SecurityConfig {
    //step 2: add user,passwords, and roles
    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){

        UserDetails leslie = User.builder()
                            .username("leslie")
                            .password("{noop}leslie123")
                            .roles("EMPLOYEE")
                            .build();

        UserDetails emma = User.builder()
                .username("emma")
                .password("{noop}emma123")
                .roles("EMPLOYEE","MANAGER")
                .build();

        UserDetails jaun = User.builder()
                .username("jaun")
                .password("{noop}jaun123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();
    //since we defined users here, spring boot will not use user/pass from application.properties file
        return new InMemoryUserDetailsManager(leslie, emma, jaun);
    }
}
