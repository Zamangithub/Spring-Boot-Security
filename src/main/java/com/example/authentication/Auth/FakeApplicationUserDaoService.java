package com.example.authentication.Auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.authentication.Security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
        }


    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(

                "gul",
                passwordEncoder.encode("password"),
                STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true
        ),
        new ApplicationUser(

                "linda",
                passwordEncoder.encode("password123"),
                ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true
        ),
                new ApplicationUser(

                        "Azan",
                        passwordEncoder.encode("password123"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ));

        return applicationUsers;

    }
}
