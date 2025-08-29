package com.springboot.cruddemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

//step 1
@Configuration
public class SecurityConfig {
    //add support for jdbc ... no more hardcore users
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        //define query to retrieve user by username
        jdbcUserDetailsManager.setUsersByUsernameQuery("select user_id,password,active from members where user_id=?");

        //define query to retrieve authorities/roles by username
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery("select user_id,role from roles where user_id=?"); //? will replace the value from login

        return jdbcUserDetailsManager;
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

    /*
    //step 2: add user,passwords, and roles
    //hard coded users, in memory
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
     */

    /*
    @Bean                                       //inject datasource which is autoconfigured by spring boot
    public UserDetailsManager userDetailsmanager(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);  //no longer hardcoding users mn
                  // tell springboot security to use JDBC authentication with our datasource
    }
     */
}
