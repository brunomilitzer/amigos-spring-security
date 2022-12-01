package com.brunomilitzer.demo.security;

import com.brunomilitzer.demo.auth.ApplicationUserService;
import com.brunomilitzer.demo.jwt.JwtConfig;
import com.brunomilitzer.demo.jwt.JwtSecretKey;
import com.brunomilitzer.demo.jwt.JwtTokenVerifier;
import com.brunomilitzer.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static com.brunomilitzer.demo.security.UserPermission.COURSES_WRITE;
import static com.brunomilitzer.demo.security.UserRole.ADMIN;
import static com.brunomilitzer.demo.security.UserRole.ADMIN_TRAINEE;
import static com.brunomilitzer.demo.security.UserRole.STUDENT;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService userService;

    private final JwtConfig jwtConfig;

    private final JwtSecretKey jwtSecretKey;

    @Autowired
    public ApplicationSecurityConfig(
            final PasswordEncoder passwordEncoder,
            final ApplicationUserService userService,
            final JwtConfig jwtConfig,
            final JwtSecretKey jwtSecretKey
    ) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.jwtConfig = jwtConfig;
        this.jwtSecretKey = jwtSecretKey;
    }

    @Bean
    public SecurityFilterChain securityFilterChain( final HttpSecurity http ) throws Exception {
        http
                //.csrf(csrf -> csrf.csrfTokenRepository( CookieCsrfTokenRepository.withHttpOnlyFalse() )) // Use for production
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy( STATELESS ).and()
                .addFilter( this.usernameAndPasswordAuthenticationFilter( http ) )
                .addFilterAfter( new JwtTokenVerifier( this.jwtConfig, this.jwtSecretKey ),
                        JwtUsernameAndPasswordAuthenticationFilter.class )
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
                .anyRequest().authenticated();

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder( this.passwordEncoder );
        provider.setUserDetailsService( this.userService );

        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            final AuthenticationConfiguration authenticationConfiguration ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    public JwtUsernameAndPasswordAuthenticationFilter usernameAndPasswordAuthenticationFilter(
            final HttpSecurity http ) throws Exception {
        return new JwtUsernameAndPasswordAuthenticationFilter(
                this.authenticationManager(
                        http.getSharedObject( AuthenticationConfiguration.class ) ),
                this.jwtConfig, this.jwtSecretKey );
    }

}
