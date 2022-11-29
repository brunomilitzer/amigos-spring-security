package com.brunomilitzer.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.brunomilitzer.demo.security.UserPermission.COURSES_WRITE;
import static com.brunomilitzer.demo.security.UserRole.ADMIN;
import static com.brunomilitzer.demo.security.UserRole.ADMIN_TRAINEE;
import static com.brunomilitzer.demo.security.UserRole.STUDENT;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig( final PasswordEncoder passwordEncoder ) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain( final HttpSecurity http ) throws Exception {
        http
                //.csrf(csrf -> csrf.csrfTokenRepository( CookieCsrfTokenRepository.withHttpOnlyFalse() )) // Use for production
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers( "/", "index", "/css/*", "/js/*" ).permitAll()
                .antMatchers( "/api/**" ).hasRole( STUDENT.name() )
                .antMatchers( DELETE, "/management/api/**" )
                .hasAuthority( COURSES_WRITE.getPermission() )
                .antMatchers( POST, "/management/api/**" )
                .hasAuthority( COURSES_WRITE.getPermission() )
                .antMatchers( PUT, "/management/api/**" )
                .hasAuthority( COURSES_WRITE.getPermission() )
                .antMatchers( GET, "/management/api/**" ).hasAnyRole( ADMIN.name(), ADMIN_TRAINEE.name() )
                .anyRequest().authenticated()
                .and().httpBasic();

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        final UserDetails user = User.builder().username( "vgarcez" )
                .password( passwordEncoder.encode( "password" ) )
                //.roles( STUDENT.name() )
                .authorities( STUDENT.getGrantedAuthorities() )
                .build();

        final UserDetails admin = User.builder().username( "bmilitzer" )
                .password( passwordEncoder.encode( "password" ) )
                //.roles( ADMIN.name() )
                .authorities( ADMIN.getGrantedAuthorities() )
                .build();

        final UserDetails adminTrainee = User.builder().username( "tgarcez" )
                .password( passwordEncoder.encode( "password" ) )
                //.roles( ADMIN_TRAINEE.name() )
                .authorities( ADMIN_TRAINEE.getGrantedAuthorities() )
                .build();

        return new InMemoryUserDetailsManager( user, admin, adminTrainee );
    }

}
