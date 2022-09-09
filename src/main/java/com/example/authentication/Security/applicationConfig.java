package com.example.authentication.Security;


import com.example.authentication.Auth.ApplicationUserService;
import com.example.authentication.Jwt.JwtConfig;
import com.example.authentication.Jwt.JwtTokenVerifier;
import com.example.authentication.Jwt.JwtUsernamePasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.authentication.Security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class applicationConfig extends WebSecurityConfigurerAdapter {



    private final PasswordEncoder  passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    @Autowired
    public applicationConfig(PasswordEncoder passwordEncoder,
                             ApplicationUserService applicationUserService,
                             SecretKey secretKey,
                             JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernamePasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/Js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())

                //ANT MATCHER IS ANOTHER METHOD TO SPECIFIC HOW AND WHERE USER CAN ACCESS ON SITE//
                //__AM NOT USING THIS METHOD BCOZ AM USING @Anotation method_@PreAuthorize_______________________________//
/*                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                  .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) */
                .anyRequest()
                .authenticated();


                //THIS code of block for FORM BASED Authentication//
           //now am not using becoz now i am implementing JWT
    //_____________________________________________________________________________//
              /*  .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses",true)
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID","remember-me")
                .logoutSuccessUrl("/login");
          */

    }
//HERE WE ARE DESCRIBING THREE ROLE BY "ROLES" AND "AUTHORITIES" //
// BUT NOW AM NOT USING THIS BECAUSE I DECLARE IT MY FAKE DATABASE//
    //***************************************************************//
 /*   @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails gulUser = User.builder()
                .username("gul")
                .password(passwordEncoder.encode("password"))
                //.roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails azanUser = User.builder()
                .username("Azan")
                .password(passwordEncoder.encode("password123"))
               // .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();


        return new InMemoryUserDetailsManager(
                gulUser,
                lindaUser,
                azanUser
        );

    } */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
