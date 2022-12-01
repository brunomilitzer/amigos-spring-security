package com.brunomilitzer.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtConfig jwtConfig;

    private final JwtSecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(
            AuthenticationManager authenticationManager, final JwtConfig jwtConfig, JwtSecretKey secretKey ) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(
            final HttpServletRequest request, final HttpServletResponse response ) throws AuthenticationException {

        try {
            final UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue( request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class );

            final Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), authenticationRequest.getPassword() );

            return this.authenticationManager.authenticate( authentication );

        } catch ( final IOException exception ) {
            throw new RuntimeException( exception );
        }
    }

    @Override
    protected void successfulAuthentication(
            final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain, final Authentication authResult ) {

        final Date expirationDate = Date.from( LocalDateTime
                .now().plusMinutes( this.jwtConfig.getTokenExpirationAfterMinutes() )
                .atZone( ZoneId.systemDefault() ).toInstant() );

        final String token = Jwts.builder().setSubject( authResult.getName() )
                .claim( "authorities", authResult.getAuthorities() )
                .setIssuedAt( new Date() )
                .setExpiration( expirationDate )
                .signWith( this.secretKey.getSecret() ).compact();

        response.addHeader( this.jwtConfig.getAuthorizationHeader(), this.jwtConfig.getTokenPrefix() + token );
    }

}
