package com.brunomilitzer.demo.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.security.Key;

@Configuration
public class JwtSecretKey {

    private final JwtConfig config;

    @Autowired
    public JwtSecretKey( JwtConfig config ) {
        this.config = config;
    }

    @Bean
    public SecretKey getSecret() {
        return Keys.hmacShaKeyFor( this.config.getSecretKey().getBytes() );
    }

}
