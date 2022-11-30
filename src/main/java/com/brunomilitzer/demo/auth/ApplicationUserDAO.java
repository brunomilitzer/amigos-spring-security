package com.brunomilitzer.demo.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface ApplicationUserDAO {

    Optional<ApplicationUser> selectApplicationUserByUsername( final String username );

}
