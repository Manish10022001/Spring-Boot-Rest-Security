package com.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

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
    //4
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(configurer ->
                configurer
                        .requestMatchers(HttpMethod.GET,"/employees").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET, "/employees/**").hasRole("EMPLOYEE") // USED **, means all sub-paths
                        .requestMatchers(HttpMethod.POST,"/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT,"/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PATCH,"/employees/**").hasRole("MANAGER") // ADDED request match for patch - partial update
                        .requestMatchers(HttpMethod.DELETE,"/employees/**").hasRole("ADMIN")
        );

        //use HTTP Basic authentication
        http.httpBasic(Customizer.withDefaults());

        //disable Cross Site Request Forgery(CSRF)
        //in general, not required for stateless REST APIs that use POST, PUT, DELETE, and/or PATCH
        http.csrf(csrf->csrf.disable());

        return http.build();
    }
}
