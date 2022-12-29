package com.example.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * WebSecurityConfig class is annotated with @EnableWebSecurity to enable Spring Security's web security support
 * and provide the Spring MVC integration. It also exposes two beans to set some specifics for the web security
 * configuration.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * SecurityFilterChain bean defines which URL path should be secured and which should not.
     * Specifically, / and the /home paths are configured to not require any authentication. All other paths must be authenticated.
     *
     * @param httpSecurity tag
     * @return tag
     * @throws Exception tag
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(requests -> requests.requestMatchers("/", "/home").permitAll().anyRequest().authenticated()).formLogin(form -> form.loginPage("/login").permitAll()).logout(LogoutConfigurer::permitAll);
        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder().username("user").password("pass").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }

}
