package com.security.fileencryptionsystem.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")               // Points Spring Security to your custom page
                        .defaultSuccessUrl("/", true)      // Forces redirection back to home page after entering correct credentials
                        .permitAll()
                )
                .logout(logout -> logout.permitAll());

        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        // Set up a mock secure account credential
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("SecurePass123")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}