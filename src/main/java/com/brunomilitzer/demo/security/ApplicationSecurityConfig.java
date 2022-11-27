package com.brunomilitzer.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.brunomilitzer.demo.security.UserRole.ADMIN;
import static com.brunomilitzer.demo.security.UserRole.STUDENT;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig( final PasswordEncoder passwordEncoder ) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain( final HttpSecurity http ) throws Exception {
        http.authorizeHttpRequests()
                .antMatchers( "/", "index", "/css/*", "/js/*" )
                .permitAll()
                .anyRequest().authenticated()
                .and().httpBasic();

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        final UserDetails user = User.builder().username( "vgarcez" )
                .password( passwordEncoder.encode( "password" ) ).roles( STUDENT.name() ).build();

        final UserDetails admin = User.builder().username( "bmilitzer" )
                .password( passwordEncoder.encode( "password" ) ).roles( ADMIN.name() ).build();

        return new InMemoryUserDetailsManager( user, admin );
    }

}
