package com.brunomilitzer.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.brunomilitzer.demo.security.UserRole.ADMIN;
import static com.brunomilitzer.demo.security.UserRole.ADMIN_TRAINEE;
import static com.brunomilitzer.demo.security.UserRole.STUDENT;

@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDAOService( PasswordEncoder passwordEncoder ) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername( String username ) {
        return this.getApplicationUsers().stream().filter( appUser -> appUser.getUsername().equals( username ) )
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        return Lists.newArrayList(
                new ApplicationUser(
                        "vgarcez",
                        passwordEncoder.encode( "password" ),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "tgarcez",
                        passwordEncoder.encode( "password" ),
                        ADMIN_TRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "bmilitzer",
                        passwordEncoder.encode( "password" ),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
    }

}
