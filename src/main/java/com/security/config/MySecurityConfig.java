package com.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .antMatchers("/signin").permitAll()
            .antMatchers("/public/**").hasRole("NORMAL")
            .antMatchers("/users/**").hasRole("ADMIN")
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .loginPage("/signin")
            .loginProcessingUrl("/dologin")
            .defaultSuccessUrl("/users/");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
            .withUser("john")
            .password(this.passwordEncoder().encode("doe"))
            .roles("NORMAL");

        auth.inMemoryAuthentication()
            .withUser("Kumar")
            .password(this.passwordEncoder().encode("abhishek"))
            .roles("ADMIN");
    }

    // ROLE - High Level Overview -> Normal : Read
    // Authority - permission ro read, write and update
    // ADMIN : Read, write and update authority granted

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder(10);
    }


    
}
