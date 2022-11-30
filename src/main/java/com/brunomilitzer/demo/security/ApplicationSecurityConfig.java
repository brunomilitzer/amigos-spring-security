package com.brunomilitzer.demo.security;

import com.brunomilitzer.demo.auth.ApplicationUserService;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

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

    private final ApplicationUserService userService;

    @Autowired
    public ApplicationSecurityConfig(
            final PasswordEncoder passwordEncoder, final ApplicationUserService userService ) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
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
                .and().formLogin()
                .loginPage( "/login" ).permitAll()
                .defaultSuccessUrl( "/courses", true )
                .passwordParameter( "password" )
                .usernameParameter( "username" )
                .and().rememberMe().tokenValiditySeconds( (int) TimeUnit.DAYS.toSeconds( 21 ) )
                .key( "somethingverysecured" ) // defaults to 2 weeks
                .rememberMeParameter( "remember-me" )
                .and().logout()
                .logoutUrl( "/logout" )
                .logoutRequestMatcher( new AntPathRequestMatcher( "/logout", "POST" ) )
                .clearAuthentication( true )
                .invalidateHttpSession( true )
                .deleteCookies( "JSESSIONID", "remember-me" )
                .logoutSuccessUrl( "/login" );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager( final AuthenticationConfiguration configuration ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder( this.passwordEncoder );
        provider.setUserDetailsService( this.userService );

        return provider;
    }
}
