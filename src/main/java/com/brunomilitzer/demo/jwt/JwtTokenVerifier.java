package com.brunomilitzer.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final JwtSecretKey jwtSecretKey;

    public JwtTokenVerifier( final JwtConfig jwtConfig, final JwtSecretKey jwtSecretKey ) {
        this.jwtConfig = jwtConfig;
        this.jwtSecretKey = jwtSecretKey;
    }

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain )
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader( this.jwtConfig.getAuthorizationHeader() );

        if ( Strings.isNullOrEmpty( authorizationHeader ) || !authorizationHeader
                .startsWith( this.jwtConfig.getTokenPrefix() ) ) {
            filterChain.doFilter( request, response );
            return;
        }

        try {
            final String token = authorizationHeader.replace( this.jwtConfig.getTokenPrefix(), "" );
            final Claims tokenBody = Jwts.parserBuilder().setSigningKey( this.jwtSecretKey.getSecret() ).build()
                    .parseClaimsJws( token ).getBody();

            final String username = tokenBody.getSubject();
            var authorities = (List<Map<String, String>>) tokenBody.get( "authorities" );

            final Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map( m -> new SimpleGrantedAuthority( m.get( "authority" ) ) ).collect( Collectors.toSet() );

            final Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username, null, simpleGrantedAuthorities );

            SecurityContextHolder.getContext().setAuthentication( authentication );
        } catch ( final JwtException exception ) {
            throw new IllegalStateException( "Illegal token!" );
        }

    }

}
