package com.jtspringproject.JtSpringProject.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.jtspringproject.JtSpringProject.models.Admin;
import com.jtspringproject.JtSpringProject.models.User;
import com.jtspringproject.JtSpringProject.services.adminService;
import com.jtspringproject.JtSpringProject.services.userService;

@Configuration
public class SecurityConfiguration {

    @Bean
    public DaoAuthenticationProvider adminAuthenticationProvider(
            adminService adminService,
            PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider();

        provider.setUserDetailsService(username -> {
            Admin admin = adminService.getAdminByUsername(username);

            if (admin == null) {
                throw new UsernameNotFoundException(
                        "Admin not found: " + username);
            }

            return org.springframework.security.core.userdetails.User
                    .withUsername(admin.getUsername())
                    .password(admin.getPassword())
                    .roles("ADMIN")
                    .build();
        });

        provider.setPasswordEncoder(passwordEncoder);

        return provider;
    }

    @Bean
    public DaoAuthenticationProvider customerAuthenticationProvider(
            userService userService,
            PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider();

        provider.setUserDetailsService(username -> {
            User user = userService.getUserByUsername(username);

            if (user == null) {
                throw new UsernameNotFoundException(
                        "Customer not found: " + username);
            }

            return org.springframework.security.core.userdetails.User
                    .withUsername(user.getUsername())
                    .password(user.getPassword())
                    .roles("USER")
                    .build();
        });

        provider.setPasswordEncoder(passwordEncoder);

        return provider;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain adminFilterChain(
            HttpSecurity http,
            DaoAuthenticationProvider adminAuthenticationProvider)
            throws Exception {

        http.antMatcher("/admin/**")
                .authenticationProvider(adminAuthenticationProvider)
                .authorizeRequests()
                .antMatchers("/admin/login").permitAll()
                .anyRequest().hasRole("ADMIN");

        http.formLogin()
                .loginPage("/admin/login")
                .loginProcessingUrl("/admin/loginvalidate")
                .successHandler((request, response, authentication) -> {
                    response.sendRedirect("/admin/");
                })
                .failureHandler((request, response, exception) -> {
                    response.sendRedirect("/admin/login?error=true");
                });

        http.logout()
                .logoutRequestMatcher(
                        new AntPathRequestMatcher("/admin/logout", "GET"))
                .logoutSuccessUrl("/admin/login")
                .deleteCookies("JSESSIONID");

        http.exceptionHandling()
                .accessDeniedPage("/403");

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain customerFilterChain(
            HttpSecurity http,
            DaoAuthenticationProvider customerAuthenticationProvider)
            throws Exception {

        http.authenticationProvider(customerAuthenticationProvider)
                .authorizeRequests()
                .antMatchers(
                        "/login",
                        "/register",
                        "/newuserregister",
                        "/403")
                .permitAll()
                .anyRequest().hasRole("USER");

        http.formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/userloginvalidate")
                .successHandler((request, response, authentication) -> {
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> {
                    response.sendRedirect("/login?error=true");
                });

        http.logout()
                .logoutRequestMatcher(
                        new AntPathRequestMatcher("/logout", "GET"))
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID");

        http.exceptionHandling()
                .accessDeniedPage("/403");

        return http.build();
    }
}