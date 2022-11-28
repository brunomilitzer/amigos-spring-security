package com.brunomilitzer.demo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.brunomilitzer.demo.security.UserPermission.COURSES_READ;
import static com.brunomilitzer.demo.security.UserPermission.COURSES_WRITE;
import static com.brunomilitzer.demo.security.UserPermission.STUDENT_READ;
import static com.brunomilitzer.demo.security.UserPermission.STUDENT_WRITE;

public enum UserRole {
    STUDENT( Sets.newHashSet()),
    ADMIN(Sets.newHashSet(STUDENT_READ, STUDENT_WRITE, COURSES_READ, COURSES_WRITE)),
    ADMIN_TRAINEE(Sets.newHashSet(STUDENT_READ, COURSES_READ));

    private final Set<UserPermission> permissions;

    UserRole( Set<UserPermission> permissions ) {
        this.permissions = permissions;
    }

    public Set<UserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        final Set<SimpleGrantedAuthority> permissions = this.getPermissions().stream()
                .map( permission -> new SimpleGrantedAuthority( permission.getPermission() ) )
                .collect( Collectors.toSet() );

        permissions.add( new SimpleGrantedAuthority( "ROLE_" + this.name() ) );

        return permissions;
    }
}
