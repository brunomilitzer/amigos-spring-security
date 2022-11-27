package com.brunomilitzer.demo.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.brunomilitzer.demo.security.UserPermission.COURSES_READ;
import static com.brunomilitzer.demo.security.UserPermission.COURSES_WRITE;
import static com.brunomilitzer.demo.security.UserPermission.STUDENT_READ;
import static com.brunomilitzer.demo.security.UserPermission.STUDENT_WRITE;

public enum UserRole {
    STUDENT( Sets.newHashSet()),
    ADMIN(Sets.newHashSet(STUDENT_READ, STUDENT_WRITE, COURSES_READ, COURSES_WRITE));

    private final Set<UserPermission> permissions;

    UserRole( Set<UserPermission> permissions ) {
        this.permissions = permissions;
    }

    public Set<UserPermission> getPermissions() {
        return permissions;
    }
}
